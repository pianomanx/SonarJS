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
// https://sonarsource.github.io/rspec/#/rspec/S4823/javascript

import type { Rule } from 'eslint';
import type estree from 'estree';
import { generateMeta, isMemberExpression } from '../helpers/index.js';
import * as meta from './generated-meta.js';

export const rule: Rule.RuleModule = {
  meta: generateMeta(meta, {
    messages: {
      safeArg: `Make sure that command line arguments are used safely here.`,
    },
  }),
  create(context: Rule.RuleContext) {
    return {
      MemberExpression(node: estree.Node) {
        if (isMemberExpression(node, 'process', 'argv')) {
          context.report({
            messageId: 'safeArg',
            node,
          });
        }
      },
    };
  },
};
