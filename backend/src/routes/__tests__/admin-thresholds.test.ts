/**
 * Test: admin-thresholds validation helpers
 *
 * Unit tests for the input validation and advanced_overrides allow-listing
 * logic used by PUT /api/admin/thresholds (HIGH finding 5: previously the
 * route spread arbitrary advanced_overrides keys onto the threshold update
 * payload without type/range checks on the core thresholds).
 */
import { describe, it, expect, vi } from 'vitest';

// The route module pulls in DynamicThresholdManager (which transitively
// imports the database client) and the JWT auth middleware. Neither is
// needed to exercise the pure validation/allow-list helpers under test,
// so they're mocked out to keep this a lightweight unit test.
vi.mock('@/config/dynamicThresholds.js', () => ({
  DynamicThresholdManager: { getInstance: vi.fn(() => ({})) }
}));

vi.mock('@/middleware/auth.js', () => ({
  authenticateJWT: (_req: any, _res: any, next: any) => next(),
  requireAdminRole: () => (_req: any, _res: any, next: any) => next()
}));

vi.mock('@/utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

import {
  isNumberInRange,
  validateThresholdPercentages,
  sanitizeAdvancedOverrides
} from '../admin-thresholds.js';

describe('isNumberInRange', () => {
  it('accepts a finite number within bounds', () => {
    expect(isNumberInRange(50, 0, 100)).toBe(true);
    expect(isNumberInRange(0, 0, 100)).toBe(true);
    expect(isNumberInRange(100, 0, 100)).toBe(true);
  });

  it('rejects out-of-range numbers', () => {
    expect(isNumberInRange(-1, 0, 100)).toBe(false);
    expect(isNumberInRange(101, 0, 100)).toBe(false);
  });

  it('rejects non-numbers, NaN, and Infinity', () => {
    expect(isNumberInRange('50', 0, 100)).toBe(false);
    expect(isNumberInRange(null, 0, 100)).toBe(false);
    expect(isNumberInRange(undefined, 0, 100)).toBe(false);
    expect(isNumberInRange(NaN, 0, 100)).toBe(false);
    expect(isNumberInRange(Infinity, 0, 100)).toBe(false);
    expect(isNumberInRange({}, 0, 100)).toBe(false);
  });
});

describe('validateThresholdPercentages', () => {
  it('returns null for valid, well-ordered percentages', () => {
    expect(validateThresholdPercentages(85, 60)).toBeNull();
    expect(validateThresholdPercentages(0, 0)).toBeNull();
    expect(validateThresholdPercentages(100, 100)).toBeNull();
  });

  it('rejects a non-numeric auto_approve_threshold', () => {
    expect(validateThresholdPercentages('85', 60)).toMatch(/auto_approve_threshold/);
  });

  it('rejects a non-numeric manual_review_threshold', () => {
    expect(validateThresholdPercentages(85, '60')).toMatch(/manual_review_threshold/);
  });

  it('rejects out-of-range values', () => {
    expect(validateThresholdPercentages(150, 60)).toMatch(/auto_approve_threshold/);
    expect(validateThresholdPercentages(85, -10)).toMatch(/manual_review_threshold/);
  });

  it('rejects manual_review_threshold greater than auto_approve_threshold', () => {
    expect(validateThresholdPercentages(60, 85)).toMatch(/must not be greater than/);
  });
});

describe('sanitizeAdvancedOverrides', () => {
  it('passes through allow-listed keys with valid [0,1] values', () => {
    const result = sanitizeAdvancedOverrides({
      photoConsistency: 0.75,
      faceMatchingProduction: 0.9
    });
    expect('sanitized' in result).toBe(true);
    if ('sanitized' in result) {
      expect(result.sanitized).toEqual({
        photoConsistency: 0.75,
        faceMatchingProduction: 0.9
      });
    }
  });

  it('rejects an unknown key instead of spreading it through', () => {
    const result = sanitizeAdvancedOverrides({
      __proto__: 'polluted',
      maliciousKey: 'drop tables'
    } as unknown as Record<string, unknown>);
    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error).toMatch(/Unknown advanced_overrides key/);
    }
  });

  it('rejects an allow-listed key whose value is out of the [0,1] range', () => {
    const result = sanitizeAdvancedOverrides({ qualityMinimum: 1.5 });
    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error).toMatch(/qualityMinimum must be a number between 0 and 1/);
    }
  });

  it('rejects a non-numeric value for an allow-listed key', () => {
    const result = sanitizeAdvancedOverrides({ ocrConfidence: 'high' as unknown as number });
    expect('error' in result).toBe(true);
  });

  it('returns an empty sanitized object for an empty input', () => {
    const result = sanitizeAdvancedOverrides({});
    expect('sanitized' in result).toBe(true);
    if ('sanitized' in result) {
      expect(result.sanitized).toEqual({});
    }
  });
});
