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
import { rule } from './index.js';
import { DefaultParserRuleTester } from '../../../tests/tools/testers/rule-tester.js';
import { describe, it } from 'node:test';

describe('S5730', () => {
  it('S5730', () => {
    const ruleTester = new DefaultParserRuleTester();
    ruleTester.run('Allowing mixed-content is security-sensitive', rule, {
      valid: [
        {
          code: `
        const csp = require('helmet-csp')
        const express = require('express');
        const app = express();
        app.use(
          csp({
            directives: {
              "block-all-mixed-content": []
            }
          })
        );`,
        },
        {
          code: `
        const csp = require('helmet-csp')
        const express = require('express');
        const app = express();
        app.use(
          csp({
            directives: {
              blockAllMixedContent: []
            }
          })
        );`,
        },
        {
          code: `
        const helmet = require('helmet');
        const express = require('express');
        const app = express();
        app.use(
          helmet()
        );`,
        },
        {
          code: `
        const helmet = require('helmet');
        const express = require('express');
        const app = express();
        app.use(
          helmet.contentSecurityPolicy()
        );`,
        },
        {
          code: `
        const helmet = require('helmet');
        const express = require('express');
        const app = express();
        app.use(
          helmet.contentSecurityPolicy({
            directives: {
              "block-all-mixed-content": []
            }
          })
        );`,
        },
        {
          code: `
        const helmet = require('helmet');
        const express = require('express');
        const app = express();
        app.use(
          helmet.contentSecurityPolicy({
            directives: {
              blockAllMixedContent: []
            }
          })
        );`,
        },
        {
          code: `
        const express = require('express');
        const app = express();
        app.use(
          whatever({
            directives: {
              defaultSrc: ["'self'", 'example.com', 'code.jquery.com'],
            }
          })
        );`,
        },
        {
          code: `
        const express = require('express');
        const app = express();
        app.use(
          unknown.whatever({
            directives: {
              defaultSrc: ["'self'", 'example.com', 'code.jquery.com'],
            }
          })
        );`,
        },
      ],
      invalid: [
        {
          code: `
        const csp = require('helmet-csp')
        const express = require('express');
        const app = express();
        app.use(
          csp({
            directives: {},
          })
        );`,
          errors: [
            {
              message: JSON.stringify({
                message: `Make sure allowing mixed-content is safe here.`,
                secondaryLocations: [
                  {
                    column: 12,
                    line: 7,
                    endColumn: 26,
                    endLine: 7,
                  },
                ],
              }),
              line: 5,
              endLine: 9,
              column: 9,
              endColumn: 10,
            },
          ],
          settings: { sonarRuntime: true },
        },
        {
          code: `
        const csp = require('helmet-csp')
        const express = require('express');
        const app = express();
        app.use(
          csp({
            directives: {
              defaultSrc: ["'self'", 'example.com', 'code.jquery.com'],
            }
          })
        );`,
          errors: 1,
        },
        {
          code: `
        const helmet = require('helmet');
        const express = require('express');
        const app = express();
        app.use(
          helmet.contentSecurityPolicy({
            directives: {}
          })
        );`,
          errors: 1,
        },
        {
          code: `
        const helmet = require('helmet');
        const express = require('express');
        const app = express();
        app.use(
          helmet.contentSecurityPolicy({
            directives: {
              defaultSrc: ["'self'", 'example.com', 'code.jquery.com'],
            }
          })
        );`,
          errors: 1,
        },
      ],
    });
  });
});
