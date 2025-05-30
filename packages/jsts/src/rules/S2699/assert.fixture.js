const assert = require('assert');
const { expectEquals } = require('jest');
const { ok } = require('assert');
const vitest = require('vitest');

describe('global assert', () => {
  it('should recognize assert', () => { // Compliant
    expectEquals(10);
    assert(4);
  });

  it('should recognize assert.XXX methods', () => {  // Compliant
    assert.deepStrictEqual({ a: 1 }, { a: '1' });
  });

  it('should recognize methods from assert', () => {  // Compliant
    ok(true);
  });

  it('should recognize issue', () => { // Noncompliant {{Add at least one assertion to this test case.}}
    const x = 10;
  });
});
