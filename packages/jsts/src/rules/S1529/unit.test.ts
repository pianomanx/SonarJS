/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2025 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Sonar Source-Available License Version 1, as published by SonarSource SA.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the Sonar Source-Available License for more details.
 *
 * You should have received a copy of the Sonar Source-Available License
 * along with this program; if not, see https://sonarsource.com/license/ssal/
 */
import { DefaultParserRuleTester, RuleTester } from '../../../tests/tools/testers/rule-tester.js';
import { rule } from './index.js';
import { describe, it } from 'node:test';

describe('S1529', () => {
  it('S1529', () => {
    const ruleTesterJs = new DefaultParserRuleTester();

    const ruleTesterTs = new RuleTester();

    ruleTesterJs.run(`JS: Bitwise operators should not be used in boolean contexts`, rule, {
      valid: [
        {
          code: `// ok with numeric literal
let a = 1;
if (a & 1) {
}
`,
        },
      ],
      invalid: [
        {
          code: `// not ok, FP because javascript parser has no type information, no issue with typescript parser
let a = 1;
let b = 1;
if (a & b) {
}
`,
          errors: [
            {
              message:
                'Review this use of bitwise "&" operator; conditional "&&" might have been intended.',
              line: 4,
              endLine: 4,
              column: 7,
              endColumn: 8,
            },
          ],
        },
      ],
    });

    ruleTesterTs.run(`TS: Bitwise operators should not be used in boolean contexts`, rule, {
      valid: [
        {
          code: `// ok with numeric type number 
let a = 1;
let b = 5;
if (a & b) {
}
`,
        },
        {
          code: `// ok with numeric type bigint 
function f(a: bigint | number, b: any) {
  if (a & b) {
  }
}
`,
        },
        {
          code: `// ok with numeric type in an union 
function f(a: bigint | string, b: any) {
  if (a & b) {
  }
}
`,
        },
        {
          code: `// ok with numeric type of an enum
enum Direction { Up = 1, Down }
let b = Direction.Up;
if (a & b) {
}
`,
        },
        {
          code: `// ok for init
for (x = a & b; x < 10; x++) { // OK, not condition
}
`,
        },
        {
          code: `// ok for no condition
for (x = a & b; ; x++) { // OK, not condition
}
`,
        },
        {
          code: `// ok outside condition
foo(a & b); // OK, not inside condition

foo(a + b);
`,
        },
        {
          code: `// file ok several suspicious
if (a & b) { // OK, as there are 2 operations "&" and "|" on line 5
}

if (a | c) {
}
`,
        },
        {
          code: `// ok with bitwise operator
if (a & b) { // OK, as ">>>" is used further
}

a = x >>> y;
`,
        },
        {
          code: `// ok with literal
if (a & b) { // OK, as "|" is used as bitwise further
}

if (a | 1) {
}
`,
        },
      ],
      invalid: [
        {
          code: `// not ok with type "any"
function f(a: any, b: any) {
    if (a | b) {
    }
    // '|' in joined types are ignored
    const c: string | number = 2;
}
`,
          errors: [
            {
              message:
                'Review this use of bitwise "|" operator; conditional "||" might have been intended.',
              line: 3,
              endLine: 3,
              column: 11,
              endColumn: 12,
            },
          ],
        },
        {
          code: `// not ok do while
do {
} while (a /*comment*/ | b); // Noncompliant
a = x && y;      
`,
          errors: [
            {
              message:
                'Review this use of bitwise "|" operator; conditional "||" might have been intended.',
              line: 3,
              endLine: 3,
              column: 24,
              endColumn: 25,
            },
          ],
        },
        {
          code: `// not ok if
if (a & b) { // Noncompliant
}
a = x && y;     
`,
          errors: [
            {
              message:
                'Review this use of bitwise "&" operator; conditional "&&" might have been intended.',
              line: 2,
              endLine: 2,
              column: 7,
              endColumn: 8,
            },
          ],
        },
        {
          code: `// not ok ternary
x = a & b ? 1 : 2; // Noncompliant
a = x && y;
`,
          errors: [
            {
              message:
                'Review this use of bitwise "&" operator; conditional "&&" might have been intended.',
              line: 2,
              endLine: 2,
              column: 7,
              endColumn: 8,
            },
          ],
        },
        {
          code: `// not ok while
while ((a | b) && c) { // Noncompliant
//        ^
}
a = x && y;
`,
          errors: [
            {
              message:
                'Review this use of bitwise "|" operator; conditional "||" might have been intended.',
              line: 2,
              endLine: 2,
              column: 11,
              endColumn: 12,
            },
          ],
        },
      ],
    });
  });
});
