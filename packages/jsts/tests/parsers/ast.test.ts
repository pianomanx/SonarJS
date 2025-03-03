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
import path from 'path';

import { Parser, parsersMap } from '../../src/parsers/eslint.js';
import type { TSESTree } from '@typescript-eslint/utils';
import { describe, test } from 'node:test';
import { expect } from 'expect';
import { readFile } from '../../../shared/src/helpers/files.js';
import { JsTsAnalysisInput } from '../../src/analysis/analysis.js';
import { buildParserOptions } from '../../src/parsers/options.js';
import {
  deserializeProtobuf,
  NODE_TYPE_ENUM,
  parseInProtobuf,
  serializeInProtobuf,
  visitNode,
} from '../../src/parsers/ast.js';
import { parse } from '../../src/parsers/parse.js';

const parseFunctions = [
  {
    parser: parsersMap.javascript,
    usingBabel: true,
    errorMessage: 'Unterminated string constant. (1:0)',
  },
  {
    parser: parsersMap.typescript,
    usingBabel: false,
    errorMessage: 'Unterminated string literal.',
  },
];

async function parseSourceFile(filePath: string, parser: Parser, usingBabel = false) {
  const fileContent = await readFile(filePath);
  const fileType = 'MAIN';

  const input = { filePath, fileType, fileContent } as JsTsAnalysisInput;
  const options = buildParserOptions(input, usingBabel);
  return parse(fileContent, parser, options);
}

async function parseSourceCode(code: string, parser: Parser) {
  return parse(code, parser, {
    comment: true,
    loc: true,
    range: true,
    tokens: true,
  }).sourceCode.ast;
}

describe('ast', () => {
  describe('serializeInProtobuf()', () => {
    parseFunctions.forEach(({ parser, usingBabel }) =>
      test('should not lose information between serialize and deserializing JavaScript', async () => {
        const filePath = path.join(import.meta.dirname, 'fixtures', 'ast', 'base.js');
        const sc = await parseSourceFile(filePath, parser, usingBabel);
        const protoMessage = parseInProtobuf(sc.sourceCode.ast as TSESTree.Program);
        const serialized = serializeInProtobuf(sc.sourceCode.ast as TSESTree.Program);
        const deserializedProtoMessage = deserializeProtobuf(serialized);
        compareASTs(protoMessage, deserializedProtoMessage);
      }),
    );
  });
  test('should encode unknown nodes', async () => {
    const filePath = path.join(import.meta.dirname, 'fixtures', 'ast', 'unknownNode.ts');
    const sc = await parseSourceFile(filePath, parsersMap.typescript);
    const protoMessage = parseInProtobuf(sc.sourceCode.ast as TSESTree.Program);
    expect((protoMessage as any).program.body[0].type).toEqual(
      NODE_TYPE_ENUM.values['UnknownNodeType'],
    );
  });
  test('should support TSAsExpression nodes', async () => {
    const code = `const foo = '5' as string;`;
    const ast = await parseSourceCode(code, parsersMap.typescript);
    const serializedAST = visitNode(ast as TSESTree.Program);

    // we are only interested in checking that the serialized AST only contains nodes relevant at runtime
    expect(serializedAST.type).toEqual(0); // Program
    expect(serializedAST.program.body[0].type).toEqual(
      NODE_TYPE_ENUM.values['VariableDeclarationType'],
    ); // VariableDeclaration
    expect(serializedAST.program.body[0].variableDeclaration.declarations[0].type).toEqual(
      NODE_TYPE_ENUM.values['VariableDeclaratorType'],
    ); // VariableDeclarator
    expect(
      serializedAST.program.body[0].variableDeclaration.declarations[0].variableDeclarator.id.type,
    ).toEqual(NODE_TYPE_ENUM.values['IdentifierType']); // Identifier
    expect(
      serializedAST.program.body[0].variableDeclaration.declarations[0].variableDeclarator.init
        .type,
    ).toEqual(NODE_TYPE_ENUM.values['LiteralType']); // Literal
  });

  test('should support TSSatisfiesExpression nodes', async () => {
    const code = `42 satisfies Bar;`;
    const ast = await parseSourceCode(code, parsersMap.typescript);
    const serializedAST = visitNode(ast as TSESTree.Program);
    const literalNode = serializedAST.program.body[0].expressionStatement.expression.literal;
    expect(literalNode.type).toEqual(NODE_TYPE_ENUM.values['Literal']);
    expect(literalNode.valueNumber).toEqual(42);
  });

  test('should support TSNonNullExpression nodes', async () => {
    const code = `foo!;`;
    const ast = await parseSourceCode(code, parsersMap.typescript);
    const serializedAST = visitNode(ast as TSESTree.Program);

    const identifier = serializedAST.program.body[0].expressionStatement.expression;
    expect(identifier.type).toEqual(NODE_TYPE_ENUM.values['IdentifierType']);
    expect(identifier.identifier.name).toEqual('foo');
  });

  test('should support TSTypeAssertion nodes', async () => {
    const code = `<Foo>foo;`;
    const ast = await parseSourceCode(code, parsersMap.typescript);
    const serializedAST = visitNode(ast as TSESTree.Program);

    const identifier = serializedAST.program.body[0].expressionStatement.expression;
    expect(identifier.type).toEqual(NODE_TYPE_ENUM.values['IdentifierType']);
    expect(identifier.identifier.name).toEqual('foo');
  });

  test('should support TSParameterProperty nodes', async () => {
    const code = `
    class Point {
      constructor(public foo: number) {}
    }
    `;
    const ast = await parseSourceCode(code, parsersMap.typescript);
    const serializedAST = visitNode(ast as TSESTree.Program);

    const classDeclaration = serializedAST.program.body[0].classDeclaration;
    const methodDefinition = classDeclaration.body.classBody.body[0].methodDefinition;
    const functionParameter = methodDefinition.value.functionExpression.params[0];
    expect(functionParameter.type).toEqual(NODE_TYPE_ENUM.values['IdentifierType']);
    expect(functionParameter.identifier.name).toEqual('foo');
  });

  test('should support TSExportAssignment nodes', async () => {
    const code = `export = foo();`;
    const ast = await parseSourceCode(code, parsersMap.typescript);
    const serializedAST = visitNode(ast as TSESTree.Program);

    const expression = serializedAST.program.body[0].tSExportAssignment.expression;
    expect(expression.type).toEqual(NODE_TYPE_ENUM.values['CallExpressionType']);
    expect(expression.callExpression.callee.identifier.name).toEqual('foo');
  });

  test('should support TSImportEquals nodes with Identifier module reference', async () => {
    const code = `import a = foo;`;
    const ast = await parseSourceCode(code, parsersMap.typescript);
    const protoMessage = visitNode(ast as TSESTree.Program);

    expect(protoMessage.program.body[0].type).toEqual(
      NODE_TYPE_ENUM.values['TSImportEqualsDeclarationType'],
    );

    const tSImportEqualsDeclaration = protoMessage.program.body[0].tSImportEqualsDeclaration;
    expect(tSImportEqualsDeclaration.importKind).toEqual('value');

    let id = tSImportEqualsDeclaration.id;
    expect(id.type).toEqual(NODE_TYPE_ENUM.values['IdentifierType']);
    expect(id.identifier.name).toEqual('a');

    let moduleReference = tSImportEqualsDeclaration.moduleReference;
    expect(moduleReference.type).toEqual(NODE_TYPE_ENUM.values['IdentifierType']);
    expect(moduleReference.identifier.name).toEqual('foo');

    const serialized = serializeInProtobuf(ast as TSESTree.Program);
    const deserializedProtoMessage = deserializeProtobuf(serialized);
    compareASTs(protoMessage, deserializedProtoMessage);
  });

  test('should support TSImportEquals nodes with TSQualifiedName module reference', async () => {
    const code = `import a = a.b.c;`;
    const ast = await parseSourceCode(code, parsersMap.typescript);
    const protoMessage = visitNode(ast as TSESTree.Program);

    expect(protoMessage.program.body[0].type).toEqual(
      NODE_TYPE_ENUM.values['TSImportEqualsDeclarationType'],
    );

    const tSImportEqualsDeclaration = protoMessage.program.body[0].tSImportEqualsDeclaration;
    expect(tSImportEqualsDeclaration.importKind).toEqual('value');

    let id = tSImportEqualsDeclaration.id;
    expect(id.type).toEqual(NODE_TYPE_ENUM.values['IdentifierType']);
    expect(id.identifier.name).toEqual('a');
    expect(tSImportEqualsDeclaration.moduleReference.type).toEqual(
      NODE_TYPE_ENUM.values['TSQualifiedNameType'],
    );

    let tSQualifiedName = tSImportEqualsDeclaration.moduleReference.tSQualifiedName;
    expect(tSQualifiedName.right.type).toEqual(NODE_TYPE_ENUM.values['IdentifierType']);
    expect(tSQualifiedName.right.identifier.name).toEqual('c');
    expect(tSQualifiedName.left.type).toEqual(NODE_TYPE_ENUM.values['TSQualifiedNameType']);
    expect(tSQualifiedName.left.tSQualifiedName.left.identifier.name).toEqual('a');
    expect(tSQualifiedName.left.tSQualifiedName.right.identifier.name).toEqual('b');

    const serialized = serializeInProtobuf(ast as TSESTree.Program);
    const deserializedProtoMessage = deserializeProtobuf(serialized);
    compareASTs(protoMessage, deserializedProtoMessage);
  });

  test('should support TSImportEquals nodes with TSExternalModuleReference', async () => {
    const code = `import a = require('foo');`;
    const ast = await parseSourceCode(code, parsersMap.typescript);
    const protoMessage = visitNode(ast as TSESTree.Program);

    expect(protoMessage.program.body[0].type).toEqual(
      NODE_TYPE_ENUM.values['TSImportEqualsDeclarationType'],
    );

    const tSImportEqualsDeclaration = protoMessage.program.body[0].tSImportEqualsDeclaration;
    expect(tSImportEqualsDeclaration.importKind).toEqual('value');

    let id = tSImportEqualsDeclaration.id;
    expect(id.type).toEqual(NODE_TYPE_ENUM.values['IdentifierType']);
    expect(id.identifier.name).toEqual('a');
    expect(tSImportEqualsDeclaration.moduleReference.type).toEqual(
      NODE_TYPE_ENUM.values['TSExternalModuleReferenceType'],
    );

    const tSExternalModuleReference =
      tSImportEqualsDeclaration.moduleReference.tSExternalModuleReference;
    expect(tSExternalModuleReference.expression.literal.valueString).toEqual('foo');

    const serialized = serializeInProtobuf(ast as TSESTree.Program);
    const deserializedProtoMessage = deserializeProtobuf(serialized);
    compareASTs(protoMessage, deserializedProtoMessage);
  });

  test('should support TSImportEquals nodes with type TSExternalModuleReference', async () => {
    const code = `import type a = require('foo');`;
    const ast = await parseSourceCode(code, parsersMap.typescript);
    const protoMessage = visitNode(ast as TSESTree.Program);

    expect(protoMessage.program.body[0].type).toEqual(
      NODE_TYPE_ENUM.values['TSImportEqualsDeclarationType'],
    );

    const tSImportEqualsDeclaration = protoMessage.program.body[0].tSImportEqualsDeclaration;
    expect(tSImportEqualsDeclaration.importKind).toEqual('type');

    let id = tSImportEqualsDeclaration.id;
    expect(id.type).toEqual(NODE_TYPE_ENUM.values['IdentifierType']);
    expect(id.identifier.name).toEqual('a');
    expect(tSImportEqualsDeclaration.moduleReference.type).toEqual(
      NODE_TYPE_ENUM.values['TSExternalModuleReferenceType'],
    );

    const tSExternalModuleReference =
      tSImportEqualsDeclaration.moduleReference.tSExternalModuleReference;
    expect(tSExternalModuleReference.expression.literal.valueString).toEqual('foo');

    const serialized = serializeInProtobuf(ast as TSESTree.Program);
    const deserializedProtoMessage = deserializeProtobuf(serialized);
    compareASTs(protoMessage, deserializedProtoMessage);
  });
});

/**
 * Put breakpoints on the lines that throw to debug the AST comparison.
 */
function compareASTs(parsedAst, deserializedAst) {
  let expected, received;
  for (const [key, value] of Object.entries(parsedAst)) {
    if (value !== undefined && deserializedAst[key] === undefined) {
      throw new Error(`Key ${key} not found in ${deserializedAst.type}`);
    }
    if (key === 'type') continue;
    if (Array.isArray(value)) {
      if (!Array.isArray(deserializedAst[key])) {
        throw new Error(`Expected array for key ${key} in ${parsedAst.type}`);
      }
      expected = value.length;
      received = deserializedAst[key].length;
      if (expected !== received) {
        throw new Error(
          `Length mismatch for key ${key} in ${parsedAst.type}. Expected ${expected}, got ${received}`,
        );
      }
      for (let i = 0; i < value.length; i++) {
        compareASTs(value[i], deserializedAst[key][i]);
      }
    } else if (typeof value === 'object') {
      compareASTs(value, deserializedAst[key]);
    } else {
      if (areDifferent(value, deserializedAst[key])) {
        throw new Error(
          `Value mismatch for key ${key} in ${parsedAst.type}. Expected ${value}, got ${deserializedAst[key]}`,
        );
      }
    }
  }

  function areDifferent(a, b) {
    if (isNullOrUndefined(a) && isNullOrUndefined(b)) return false;
    return a !== b;
    function isNullOrUndefined(a) {
      return a === null || a === undefined;
    }
  }
}
