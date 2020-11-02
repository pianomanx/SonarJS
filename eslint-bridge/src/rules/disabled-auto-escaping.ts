/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2020 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// https://jira.sonarsource.com/browse/RSPEC-5247

import { Rule } from 'eslint';
import * as estree from 'estree';
import { isRequiredParserServices } from '../utils/isRequiredParserServices';
import {
  getModuleNameOfNode,
  getPropertyWithValue,
  getValueOfExpression,
  isCallToFQN,
  isIdentifier,
  resolveFromFunctionReference,
} from './utils';

export const rule: Rule.RuleModule = {
  create(context: Rule.RuleContext) {
    const services = context.parserServices;

    function checkSensitiveCall(
      callExpression: estree.CallExpression | estree.NewExpression,
      sensitiveArgumentIndex: number,
      sensitiveProperty: string,
      sensitivePropertyValue: boolean,
    ) {
      if (callExpression.arguments.length < sensitiveArgumentIndex + 1) {
        return;
      }
      const sensitiveArgument = callExpression.arguments[sensitiveArgumentIndex];
      const options = getValueOfExpression(context, sensitiveArgument, 'ObjectExpression');
      if (!options) {
        return;
      }
      const unsafeProperty = getPropertyWithValue(
        context,
        options,
        sensitiveProperty,
        sensitivePropertyValue,
      );
      if (unsafeProperty) {
        context.report({ node: callExpression.callee, message: 'TODO' });
      }
    }

    function isEmptySanitizerFunction(
      sanitizerFunction:
        | estree.FunctionExpression
        | estree.FunctionDeclaration
        | estree.ArrowFunctionExpression,
    ) {
      if (sanitizerFunction.params.length !== 1) {
        return false;
      }
      const firstParam = sanitizerFunction.params[0];
      if (firstParam.type !== 'Identifier') {
        return false;
      }
      const firstParamName = firstParam.name;
      if (
        sanitizerFunction.body.type === 'Identifier' &&
        sanitizerFunction.body.name === firstParamName
      ) {
        return true;
      }
      if (sanitizerFunction.body.type === 'BlockStatement') {
        const { body } = sanitizerFunction.body;
        if (body.length !== 1) {
          return false;
        }
        const onlyStatement = body[0];
        if (
          onlyStatement.type === 'ReturnStatement' &&
          onlyStatement.argument &&
          isIdentifier(onlyStatement.argument, firstParamName)
        ) {
          return true;
        }
      }
      return false;
    }

    function isInvalidSanitizerFunction(node: estree.Node) {
      type AssignedFunction =
        | estree.FunctionDeclaration
        | estree.FunctionExpression
        | estree.ArrowFunctionExpression
        | undefined
        | null;
      let assignedFunction: AssignedFunction =
        getValueOfExpression(context, node, 'FunctionExpression') ||
        getValueOfExpression(context, node, 'ArrowFunctionExpression');
      if (!assignedFunction && node.type === 'Identifier' && isRequiredParserServices(services)) {
        assignedFunction = resolveFromFunctionReference(context, node);
      }
      if (!!assignedFunction) {
        return isEmptySanitizerFunction(assignedFunction);
      }
      return false;
    }

    return {
      CallExpression: (node: estree.Node) => {
        const callExpression = node as estree.CallExpression;
        if (isCallToFQN(context, callExpression, 'handlebars', 'compile')) {
          checkSensitiveCall(callExpression, 1, 'noEscape', true);
        }
        if (isCallToFQN(context, callExpression, 'marked', 'setOptions')) {
          checkSensitiveCall(callExpression, 0, 'sanitize', false);
        }
        const calleeModule = getModuleNameOfNode(context, callExpression.callee);
        if (calleeModule?.value === 'markdown-it') {
          checkSensitiveCall(callExpression, 0, 'html', true);
        }
      },
      NewExpression: (node: estree.Node) => {
        const newExpression = node as estree.NewExpression;
        const { callee } = newExpression;
        if (callee.type !== 'MemberExpression') {
          return;
        }
        const module = getModuleNameOfNode(context, callee.object);
        if (module?.value === 'kramed' && isIdentifier(callee.property, 'Renderer')) {
          checkSensitiveCall(newExpression, 0, 'sanitize', false);
        }
      },
      AssignmentExpression: (node: estree.Node) => {
        const assignmentExpression = node as estree.AssignmentExpression;
        const { left, right } = assignmentExpression;
        if (left.type !== 'MemberExpression') {
          return;
        }
        const module = getModuleNameOfNode(context, left.object);
        if (module?.value !== 'mustache' || !isIdentifier(left.property, 'escape')) {
          return;
        }
        if (isInvalidSanitizerFunction(right)) {
          context.report({ node: right, message: 'TODO' });
        }
      },
    };
  },
};
