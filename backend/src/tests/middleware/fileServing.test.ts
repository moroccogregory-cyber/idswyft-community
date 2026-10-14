import { describe, it, expect, vi, beforeEach } from 'vitest';

// fileServing.ts imports '@/config/database.js' (for the ownership lookup)
// and '@/config/index.js'. Mock both so this stays a fast, isolated unit
// test instead of requiring real DB env vars (SUPABASE_URL/DATABASE_URL).
const mockSupabase = vi.hoisted(() => ({
  from: vi.fn(),
}));

vi.mock('@/config/database.js', () => ({
  supabase: mockSupabase,
  connectDB: vi.fn(),
}));

vi.mock('@/config/index.js', () => ({
  default: {
    storage: { provider: 'local', encryption: false },
  },
}));

import { isPathSafe, safeDecode, serveLocalFile } from '../../middleware/fileServing.js';

describe('isPathSafe (path traversal guard)', () => {
  it('allows a normal relative file path', () => {
    expect(isPathSafe('uploads/documents/file.jpg')).toBe(true);
  });

  it('allows a simple filename', () => {
    expect(isPathSafe('document.pdf')).toBe(true);
  });

  it('blocks classic path traversal', () => {
    expect(isPathSafe('../etc/passwd')).toBe(false);
  });

  it('blocks traversal buried inside the path', () => {
    expect(isPathSafe('uploads/../../../etc/passwd')).toBe(false);
  });

  it('blocks absolute paths', () => {
    expect(isPathSafe('/absolute/path')).toBe(false);
    expect(isPathSafe('/etc/passwd')).toBe(false);
  });

  it('blocks URL-encoded traversal that escapes uploads base (%2e%2e)', () => {
    // %2e%2e decodes to ".." — two levels up goes outside UPLOADS_BASE
    expect(isPathSafe('%2e%2e/etc/passwd')).toBe(false);
    expect(isPathSafe('uploads/%2e%2e/%2e%2e/etc/passwd')).toBe(false);
  });

  it('blocks double-encoded traversal (%252e%252e)', () => {
    // %252e decodes to %2e on first pass, then to "." on second — classic bypass
    expect(isPathSafe('%252e%252e/%252e%252e/etc/passwd')).toBe(false);
  });
});

describe('safeDecode', () => {
  it('returns absolute path for valid relative input', () => {
    const result = safeDecode('documents/file.jpg');
    expect(result).toBeTruthy();
    expect(result).toContain('documents');
    expect(result).toContain('file.jpg');
  });

  it('returns null for path traversal', () => {
    expect(safeDecode('../../etc/passwd')).toBeNull();
  });

  it('returns null for double-encoded paths', () => {
    expect(safeDecode('%252e%252e/%252e%252e/etc/passwd')).toBeNull();
  });

  it('returns null for absolute paths', () => {
    expect(safeDecode('/etc/passwd')).toBeNull();
  });
});

// ── Cross-tenant ownership check (finding 12 fix) ──────────────────────────
//
// serveLocalFile is mounted behind authenticateAPIKey / authenticateAdminOrReviewer
// (server.ts), which proves the caller is SOME developer/reviewer/admin — but
// not that they own the specific document/selfie being fetched. These tests
// exercise the ownership gate directly, mocking fs.access (file "exists") and
// supabase.from() (the documents/selfies → verification_requests lookup).

type ChainResult = { data: any; error?: any };

/** Build a thenable supabase query-builder stub that resolves to `result`. */
function makeChain(result: ChainResult) {
  const chain: any = {
    select: () => chain,
    eq: () => chain,
    limit: () => chain,
    maybeSingle: async () => result,
  };
  return chain;
}

function mockOwnership({
  documentDeveloperId,
  selfieDeveloperId,
}: {
  documentDeveloperId?: string | null;
  selfieDeveloperId?: string | null;
}) {
  mockSupabase.from.mockImplementation((table: string) => {
    if (table === 'documents') {
      return makeChain({
        data: documentDeveloperId !== undefined ? { verification_request_id: 'vr-1' } : null,
      });
    }
    if (table === 'selfies') {
      return makeChain({
        data: selfieDeveloperId !== undefined ? { verification_request_id: 'vr-2' } : null,
      });
    }
    if (table === 'verification_requests') {
      // Only one of documentDeveloperId/selfieDeveloperId should be set per test.
      const developerId = documentDeveloperId ?? selfieDeveloperId ?? null;
      return makeChain({ data: developerId ? { developer_id: developerId } : null });
    }
    throw new Error(`Unexpected table in test: ${table}`);
  });
}

function makeRes() {
  const res: any = {
    statusCode: null as number | null,
    body: null as any,
    sentFile: null as string | null,
    status(code: number) { res.statusCode = code; return res; },
    json(body: any) { res.body = body; return res; },
    sendFile(p: string) { res.sentFile = p; return res; },
    setHeader() { return res; },
    send() { return res; },
  };
  return res;
}

vi.mock('fs/promises', () => ({
  default: {
    access: vi.fn().mockResolvedValue(undefined),
  },
}));

describe('serveLocalFile — cross-tenant ownership check', () => {
  beforeEach(() => {
    mockSupabase.from.mockReset();
  });

  it('allows the owning developer to fetch their own document', async () => {
    mockOwnership({ documentDeveloperId: 'dev-A' });
    const req: any = { params: { 0: 'documents/file.jpg' }, developer: { id: 'dev-A' } };
    const res = makeRes();

    await serveLocalFile(req, res);

    expect(res.statusCode).toBeNull();
    expect(res.sentFile).toBeTruthy();
  });

  it('denies a different developer from fetching another tenant\'s document (IDOR)', async () => {
    mockOwnership({ documentDeveloperId: 'dev-A' });
    const req: any = { params: { 0: 'documents/file.jpg' }, developer: { id: 'dev-B' } };
    const res = makeRes();

    await serveLocalFile(req, res);

    expect(res.statusCode).toBe(403);
    expect(res.sentFile).toBeNull();
  });

  it('denies access when the path has no owning document/selfie record', async () => {
    mockOwnership({});
    const req: any = { params: { 0: 'documents/unknown.jpg' }, developer: { id: 'dev-A' } };
    const res = makeRes();

    await serveLocalFile(req, res);

    expect(res.statusCode).toBe(403);
    expect(res.sentFile).toBeNull();
  });

  it('scopes reviewers to their own developer_id', async () => {
    mockOwnership({ documentDeveloperId: 'dev-A' });
    const req: any = { params: { 0: 'documents/file.jpg' }, reviewer: { developer_id: 'dev-A' } };
    const res = makeRes();

    await serveLocalFile(req, res);

    expect(res.statusCode).toBeNull();
    expect(res.sentFile).toBeTruthy();
  });

  it('denies a reviewer scoped to a different developer', async () => {
    mockOwnership({ documentDeveloperId: 'dev-A' });
    const req: any = { params: { 0: 'documents/file.jpg' }, reviewer: { developer_id: 'dev-B' } };
    const res = makeRes();

    await serveLocalFile(req, res);

    expect(res.statusCode).toBe(403);
  });

  it('lets platform admins (req.user) bypass the ownership check', async () => {
    mockOwnership({ documentDeveloperId: 'dev-A' });
    const req: any = { params: { 0: 'documents/file.jpg' }, user: { id: 'admin-1' } };
    const res = makeRes();

    await serveLocalFile(req, res);

    expect(res.statusCode).toBeNull();
    expect(res.sentFile).toBeTruthy();
    // Admin bypass never needs the ownership lookup.
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });

  it('denies a request with no developer/reviewer/admin principal at all', async () => {
    const req: any = { params: { 0: 'documents/file.jpg' } };
    const res = makeRes();

    await serveLocalFile(req, res);

    expect(res.statusCode).toBe(403);
  });
});
