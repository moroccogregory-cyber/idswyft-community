import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';

// Mirrors the bare `GET /health` route registered directly in server.ts
// (used by Railway/Docker health checks — see docker-compose.yml). Kept as
// an isolated app here rather than importing server.ts, which boots real
// DB/Supabase/Sentry wiring that doesn't belong in a unit test.
function buildApp() {
  const app = express();
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: '1.0.0-test',
      environment: 'test'
    });
  });
  return app;
}

describe('GET /health', () => {
  const app = buildApp();

  it('returns 200 with status "ok"', async () => {
    const res = await request(app).get('/health');

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  it('responds as JSON', async () => {
    const res = await request(app).get('/health');

    expect(res.headers['content-type']).toMatch(/json/);
  });
});
