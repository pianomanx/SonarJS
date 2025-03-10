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
import { rule } from './no-missing-sonar-runtime.js';
import { RuleTester } from '../../testers/rule-tester.js';

const ruleTester = new RuleTester();

ruleTester.run('sonar-runtime configuration for secondary locations', rule, {
  valid: [
    {
      code: ``,
    },
    {
      code: `
        import { toEncodedMessage } from '../helpers';`,
    },
    {
      code: `
        toEncodedMessage();`,
    },
    {
      code: `
        unknown.toEncodedMessage();`,
    },
    {
      code: `const config = {};`,
    },
    {
      code: `const config =
        {
          alpha: whatever
        };`,
    },
    {
      code: `const config =
        {
          meta: {
            whatever: something
          }
        };`,
    },
    {
      code: `const config =
        {
          meta: {
            schema: whatever
          }
        };`,
    },
    {
      code: `const config =
        {
          meta: {
            schema: [{}]
          }
        };`,
    },
    {
      code: `const config =
        {
          meta: {
            schema: [
              {
                enum: whatever
              }
            ]
          }
        };`,
    },
    {
      code: `const config =
        {
          meta: {
            schema: [
              {
                enum: []
              }
            ]
          }
        };`,
    },
    {
      code: `const config =
        {
          meta: {
            schema: [
              {
                enum: [whatever]
              }
            ]
          }
        };`,
    },
    {
      code: `const config =
        {
          meta: {
            schema: [
              {
                enum: ['whatever']
              }
            ]
          }
        };`,
    },
    {
      code: `const config =
        {
          meta: {
            schema: [
              {
                enum: ['sonar-runtime']
              }
            ]
          }
        };`,
    },
  ],
  invalid: [
    {
      code: `
        import { toEncodedMessage } from '../helpers';
        /* ... */
        toEncodedMessage(whatever);`,
      errors: [
        {
          message: `Missing enabling of secondary location support`,
          line: 2,
          endLine: 4,
          column: 9,
          endColumn: 36,
        },
      ],
    },
    {
      code: `
        import { toEncodedMessage } from '../helpers';
        /* ... */
        toEncodedMessage(whatever);
        toEncodedMessage(whatever);`,
      errors: 1,
    },
  ],
});
