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
// https://sonarsource.github.io/rspec/#/rspec/S6643/javascript

import type estree from 'estree';
import type { Rule } from 'eslint';
import { generateMeta, interceptReport } from '../helpers/index.js';
import * as meta from './generated-meta.js';

export function decorate(rule: Rule.RuleModule): Rule.RuleModule {
  return interceptReport(
    {
      ...rule,
      meta: generateMeta(meta, rule.meta),
    },
    (context, reportDescriptor) => {
      const node = (reportDescriptor as any).node as estree.Node;
      let reportedNode: estree.Node;
      if (node.type === 'CallExpression') {
        // `*.prototype` <- CallExpression
        reportedNode = node.arguments[0];
      } else {
        // `*.prototype` <- MemberExpression <- AssignmentExpression
        reportedNode = (node as estree.AssignmentExpression).left;
      }
      context.report({ ...reportDescriptor, node: reportedNode });
    },
  );
}
