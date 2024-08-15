/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2024 SonarSource SA
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
package org.sonar.plugins.javascript.bridge;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.javascript.api.estree.ESTree;
import org.sonar.plugins.javascript.bridge.protobuf.ArrayElement;
import org.sonar.plugins.javascript.bridge.protobuf.ArrayExpression;
import org.sonar.plugins.javascript.bridge.protobuf.ArrayPattern;
import org.sonar.plugins.javascript.bridge.protobuf.AssignmentExpression;
import org.sonar.plugins.javascript.bridge.protobuf.AssignmentPattern;
import org.sonar.plugins.javascript.bridge.protobuf.BinaryExpression;
import org.sonar.plugins.javascript.bridge.protobuf.BlockStatement;
import org.sonar.plugins.javascript.bridge.protobuf.CallExpression;
import org.sonar.plugins.javascript.bridge.protobuf.ChainExpression;
import org.sonar.plugins.javascript.bridge.protobuf.ClassDeclaration;
import org.sonar.plugins.javascript.bridge.protobuf.EmptyStatement;
import org.sonar.plugins.javascript.bridge.protobuf.ExportAllDeclaration;
import org.sonar.plugins.javascript.bridge.protobuf.ExportDefaultDeclaration;
import org.sonar.plugins.javascript.bridge.protobuf.ExportSpecifier;
import org.sonar.plugins.javascript.bridge.protobuf.ExpressionStatement;
import org.sonar.plugins.javascript.bridge.protobuf.ImportDefaultSpecifier;
import org.sonar.plugins.javascript.bridge.protobuf.ImportExpression;
import org.sonar.plugins.javascript.bridge.protobuf.ImportSpecifier;
import org.sonar.plugins.javascript.bridge.protobuf.Literal;
import org.sonar.plugins.javascript.bridge.protobuf.LogicalExpression;
import org.sonar.plugins.javascript.bridge.protobuf.Node;
import org.sonar.plugins.javascript.bridge.protobuf.NodeType;
import org.sonar.plugins.javascript.bridge.protobuf.Position;
import org.sonar.plugins.javascript.bridge.protobuf.Program;
import org.sonar.plugins.javascript.bridge.protobuf.SourceLocation;
import org.sonar.plugins.javascript.bridge.protobuf.StaticBlock;
import org.sonar.plugins.javascript.bridge.protobuf.UnaryExpression;
import org.sonar.plugins.javascript.bridge.protobuf.UpdateExpression;
import org.sonar.plugins.javascript.bridge.protobuf.WithStatement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

class ESTreeFactoryTest {

  @Test
  void should_create_nodes_from_serialized_data() throws IOException {
    // the clear version of serialized.proto is `packages/jsts/tests/parsers/fixtures/ast/base.js`,
    // it was generated by writing to a file the serialized data in the test `packages/jsts/tests/parsers/ast.test.ts`
    File file = Path.of("src", "test", "resources", "files", "serialized.proto").toFile();

    Node node;
    try (FileInputStream fis = new FileInputStream(file)) {
      node = Node.parseFrom(fis);
    }
    ESTree.Node root = ESTreeFactory.from(node, ESTree.Node.class);
    assertThat(root).isInstanceOf(ESTree.Program.class);
    ESTree.Program program = (ESTree.Program) root;
    assertThat(program.body()).hasSize(55);
    // Assert a few nodes.
    assertThat(program.body().get(0)).isInstanceOfSatisfying(ESTree.VariableDeclaration.class, variableDeclaration -> {
      assertThat(variableDeclaration.declarations()).hasSize(1);
      assertThat(variableDeclaration.kind()).isEqualTo("let");
      ESTree.VariableDeclarator variableDeclarator = variableDeclaration.declarations().get(0);
      assertThat(variableDeclarator.id()).isInstanceOf(ESTree.Identifier.class);
      assertThat(variableDeclarator.init()).contains(new ESTree.SimpleLiteral(
          new ESTree.Location(new ESTree.Position(20, 8), new ESTree.Position(20, 12)),
          "",
          "null"
        )
      );
    });
    assertThat(program.body().get(14)).isInstanceOfSatisfying(ESTree.IfStatement.class, ifStatement -> {
      assertThat(ifStatement.test()).isInstanceOf(ESTree.Identifier.class);
      assertThat(ifStatement.consequent()).isInstanceOf(ESTree.BlockStatement.class);
      assertThat(ifStatement.alternate()).isEmpty();
    });

    // Source code: [, , 5]
    assertThat(program.body().get(42)).isInstanceOfSatisfying(ESTree.VariableDeclaration.class, declaration -> {
      Optional<ESTree.Expression> initializer = declaration.declarations().get(0).init();
      assertThat(initializer).isPresent();
      assertThat(initializer.get()).isInstanceOfSatisfying(ESTree.ArrayExpression.class, arrayExpression -> {
        assertThat(arrayExpression.elements()).hasSize(3);
        assertThat(arrayExpression.elements().get(0)).isEmpty();
        assertThat(arrayExpression.elements().get(1)).isEmpty();
        assertThat(arrayExpression.elements().get(2)).isNotEmpty();
      });
    });
  }

  @Test
  void should_create_program() {
    Node body = Node.newBuilder()
      .setType(NodeType.BlockStatementType)
      .setBlockStatement(BlockStatement.newBuilder().build())
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ProgramType)
      .setProgram(Program.newBuilder()
        .setSourceType("script")
        .addBody(body)
        .build())
      .setLoc(SourceLocation.newBuilder()
        .setStart(Position.newBuilder().setLine(1).setColumn(2).build())
        .setEnd(Position.newBuilder().setLine(3).setColumn(4).build())
        .build())
      .build();

    ESTree.Program estreeProgram = ESTreeFactory.from(protobufNode, ESTree.Program.class);
    assertThat(estreeProgram.sourceType()).isEqualTo("script");
    assertThat(estreeProgram.loc().start().line()).isEqualTo(1);
    assertThat(estreeProgram.loc().start().column()).isEqualTo(2);
    assertThat(estreeProgram.loc().end().line()).isEqualTo(3);
    assertThat(estreeProgram.loc().end().column()).isEqualTo(4);
    assertThat(estreeProgram.body()).hasSize(1);
    ESTree.Node estreeBody = estreeProgram.body().get(0);
    assertThat(estreeBody).isInstanceOfSatisfying(ESTree.BlockStatement.class,
      blockStatement -> assertThat(blockStatement.body()).isEmpty());
  }

  @Test
  void should_create_expression_statement_when_directive_is_empty() {
    Node expressionContent = Node.newBuilder()
      .setType(NodeType.ThisExpressionType)
      .build();
    ExpressionStatement expressionStatement = ExpressionStatement.newBuilder()
      .setExpression(expressionContent)
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ExpressionStatementType)
      .setExpressionStatement(expressionStatement)
      .build();

    ESTree.Node estreeExpressionStatement = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estreeExpressionStatement).isInstanceOf(ESTree.ExpressionStatement.class);
  }

  @Test
  void should_create_directive_from_expression_statement() {
    Node expressionContent = Node.newBuilder()
      .setType(NodeType.LiteralType)
      .build();
    ExpressionStatement expressionStatement = ExpressionStatement.newBuilder()
      .setDirective("directive")
      .setExpression(expressionContent)
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ExpressionStatementType)
      .setExpressionStatement(expressionStatement)
      .build();

    ESTree.Node estreeExpressionStatement = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estreeExpressionStatement).isInstanceOfSatisfying(ESTree.Directive.class,
      directive -> assertThat(directive.directive()).isEqualTo("directive"));
  }

  @Test
  void should_create_BigIntLiteral() {
    Literal literal = Literal.newBuilder()
      .setBigint("1234")
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.LiteralType)
      .setLiteral(literal)
      .build();

    ESTree.Node estreeExpressionStatement = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estreeExpressionStatement).isInstanceOfSatisfying(ESTree.BigIntLiteral.class, bigIntLiteral -> {
      assertThat(bigIntLiteral.bigint()).isEqualTo("1234");
      assertThat(bigIntLiteral.value()).isEqualTo(new BigInteger("1234"));
      // Default value.
      assertThat(bigIntLiteral.raw()).isEmpty();
    });
  }

  @Test
  void should_create_simple_string_literal() {
    Literal literal = Literal.newBuilder()
      .setRaw("'raw'")
      .setValueString("raw")
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.LiteralType)
      .setLiteral(literal)
      .build();

    ESTree.Node estreeExpressionStatement = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estreeExpressionStatement).isInstanceOfSatisfying(ESTree.SimpleLiteral.class, simpleLiteral -> {
      assertThat(simpleLiteral.raw()).isEqualTo("'raw'");
      assertThat(simpleLiteral.value()).isEqualTo("raw");
    });
  }

  @Test
  void should_create_simple_int_literal() {
    Literal literal = Literal.newBuilder()
      .setRaw("42")
      .setValueNumber(42)
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.LiteralType)
      .setLiteral(literal)
      .build();

    ESTree.Node estreeExpressionStatement = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estreeExpressionStatement).isInstanceOfSatisfying(ESTree.SimpleLiteral.class, simpleLiteral -> {
      assertThat(simpleLiteral.raw()).isEqualTo("42");
      assertThat(simpleLiteral.value()).isEqualTo(42);
    });
  }

  @Test
  void should_create_simple_bool_literal() {
    Literal literal = Literal.newBuilder()
      .setRaw("true")
      .setValueBoolean(true)
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.LiteralType)
      .setLiteral(literal)
      .build();

    ESTree.Node estreeExpressionStatement = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estreeExpressionStatement).isInstanceOfSatisfying(ESTree.SimpleLiteral.class, simpleLiteral -> {
      assertThat(simpleLiteral.raw()).isEqualTo("true");
      assertThat(simpleLiteral.value()).isEqualTo(true);
    });
  }


  @Test
  void should_create_reg_exp_literal() {
    Literal literal = Literal.newBuilder()
      .setPattern("1234")
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.LiteralType)
      .setLiteral(literal)
      .build();

    ESTree.Node estreeExpressionStatement = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estreeExpressionStatement).isInstanceOfSatisfying(ESTree.RegExpLiteral.class, regExpLiteral -> {
      assertThat(regExpLiteral.pattern()).isEqualTo("1234");
      assertThat(regExpLiteral.flags()).isEmpty();
      // Default value.
      assertThat(regExpLiteral.raw()).isEmpty();
    });
  }

  @Test
  void should_create_reg_exp_literal_with_flag() {
    Literal literal = Literal.newBuilder()
      .setPattern("1234")
      .setFlags("flag")
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.LiteralType)
      .setLiteral(literal)
      .build();

    ESTree.Node estreeExpressionStatement = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estreeExpressionStatement).isInstanceOfSatisfying(ESTree.RegExpLiteral.class, regExpLiteral -> {
      assertThat(regExpLiteral.pattern()).isEqualTo("1234");
      assertThat(regExpLiteral.flags()).isEqualTo("flag");
      // Default value.
      assertThat(regExpLiteral.raw()).isEmpty();
    });
  }

  @Test
  void should_create_simple_null_literal() {
    // Null literal is represented as a raw value "null" in protobuf.
    // The field "value" will not be set, resulting in an empty string.
    Literal literal = Literal.newBuilder()
      .setRaw("null")
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.LiteralType)
      .setLiteral(literal)
      .build();

    ESTree.Node estreeExpressionStatement = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estreeExpressionStatement).isInstanceOfSatisfying(ESTree.SimpleLiteral.class, simpleLiteral -> {
      assertThat(simpleLiteral.raw()).isEqualTo("null");
      assertThat(simpleLiteral.value()).isEqualTo("");
    });
  }

  @Test
  void should_create_simple_call_expression() {
    CallExpression callExpression = CallExpression.newBuilder()
      .setCallee(Node.newBuilder().setType(NodeType.SuperType).build())
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.CallExpressionType)
      .setCallExpression(callExpression)
      .build();

    ESTree.Node estreeExpressionStatement = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estreeExpressionStatement).isInstanceOfSatisfying(ESTree.CallExpression.class, estreeCallExpression -> {
      assertThat(estreeCallExpression.callee()).isInstanceOf(ESTree.Super.class);
      assertThat(estreeCallExpression.arguments()).isEmpty();
    });
  }

  @Test
  void should_create_binary_expression() {
    BinaryExpression binaryExpression = BinaryExpression.newBuilder()
      .setOperator("-")
      .setLeft(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .setRight(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.BinaryExpressionType)
      .setBinaryExpression(binaryExpression)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.BinaryExpression.class, binary -> {
      assertThat(binary.left()).isInstanceOf(ESTree.ThisExpression.class);
      assertThat(binary.right()).isInstanceOf(ESTree.ThisExpression.class);
      assertThat(binary.operator()).isEqualTo(ESTree.BinaryOperator.MINUS);
    });
  }

  @Test
  void should_create_unary_expression() {
    UnaryExpression binaryExpression = UnaryExpression.newBuilder()
      .setOperator("!")
      .setArgument(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .setPrefix(true)
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.UnaryExpressionType)
      .setUnaryExpression(binaryExpression)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.UnaryExpression.class, unary -> {
      assertThat(unary.argument()).isInstanceOf(ESTree.ThisExpression.class);
      assertThat(unary.prefix()).isTrue();
      assertThat(unary.operator()).isEqualTo(ESTree.UnaryOperator.LOGICAL_NOT);
    });
  }


  @Test
  void should_create_logical_expression() {
    LogicalExpression logicalExpression = LogicalExpression.newBuilder()
      .setOperator("&&")
      .setLeft(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .setRight(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.LogicalExpressionType)
      .setLogicalExpression(logicalExpression)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.LogicalExpression.class, logical -> {
      assertThat(logical.left()).isInstanceOf(ESTree.ThisExpression.class);
      assertThat(logical.right()).isInstanceOf(ESTree.ThisExpression.class);
      assertThat(logical.operator()).isEqualTo(ESTree.LogicalOperator.AND);
    });
  }

  @Test
  void should_create_assignment_expression() {
    AssignmentExpression assignmentExpression = AssignmentExpression.newBuilder()
      .setOperator(">>>=")
      .setLeft(Node.newBuilder().setType(NodeType.ArrayPatternType).build())
      .setRight(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.AssignmentExpressionType)
      .setAssignmentExpression(assignmentExpression)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.AssignmentExpression.class, logical -> {
      assertThat(logical.left()).isInstanceOf(ESTree.ArrayPattern.class);
      assertThat(logical.right()).isInstanceOf(ESTree.ThisExpression.class);
      assertThat(logical.operator()).isEqualTo(ESTree.AssignmentOperator.UNSIGNED_RIGHT_SHIFT_ASSIGN);
    });
  }

  @Test
  void should_create_update_expression() {
    UpdateExpression updateExpression = UpdateExpression.newBuilder()
      .setOperator("--")
      .setArgument(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.UpdateExpressionType)
      .setUpdateExpression(updateExpression)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.UpdateExpression.class, logical -> {
      assertThat(logical.argument()).isInstanceOf(ESTree.ThisExpression.class);
      assertThat(logical.prefix()).isFalse();
      assertThat(logical.operator()).isEqualTo(ESTree.UpdateOperator.DECREMENT);
    });
  }

  @Test
  void should_create_export_default_declaration() {
    ClassDeclaration classDeclaration = ClassDeclaration.newBuilder()
      .setBody(Node.newBuilder().setType(NodeType.ClassBodyType).build())
      .build();
    Node classDeclarationNode = Node.newBuilder()
      .setType(NodeType.ClassDeclarationType)
      .setClassDeclaration(classDeclaration)
      .build();
    ExportDefaultDeclaration declaration = ExportDefaultDeclaration.newBuilder()
      .setDeclaration(classDeclarationNode)
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ExportDefaultDeclarationType)
      .setExportDefaultDeclaration(declaration)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.ExportDefaultDeclaration.class, export -> {
      assertThat(export.declaration()).isInstanceOf(ESTree.ClassDeclaration.class);
    });
  }

  @Test
  void should_create_assignment_pattern() {
    AssignmentPattern assignmentPattern = AssignmentPattern.newBuilder()
      .setLeft(Node.newBuilder().setType(NodeType.ArrayPatternType).build())
      .setRight(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .build();

    Node protobufNode = Node.newBuilder()
      .setType(NodeType.AssignmentPatternType)
      .setAssignmentPattern(assignmentPattern)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.AssignmentPattern.class, pattern -> {
      assertThat(pattern.left()).isInstanceOf(ESTree.ArrayPattern.class);
      assertThat(pattern.right()).isInstanceOf(ESTree.ThisExpression.class);
    });
  }

  @Test
  void should_create_import_expression() {
    ImportExpression importExpression = ImportExpression.newBuilder()
      .setSource(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .build();

    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ImportExpressionType)
      .setImportExpression(importExpression)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.ImportExpression.class, expression -> assertThat(expression.source()).isInstanceOf(ESTree.ThisExpression.class));
  }

  @Test
  void should_create_export_specifier_type() {
    ExportSpecifier exportSpecifier = ExportSpecifier.newBuilder()
      .setLocal(Node.newBuilder().setType(NodeType.IdentifierType).build())
      .setExported(Node.newBuilder().setType(NodeType.IdentifierType).build())
      .build();

    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ExportSpecifierType)
      .setExportSpecifier(exportSpecifier)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOf(ESTree.ExportSpecifier.class);
  }

  @Test
  void should_create_import_default_specifier_type() {
    ImportDefaultSpecifier importDefaultSpecifier = ImportDefaultSpecifier.newBuilder()
      .setLocal(Node.newBuilder().setType(NodeType.IdentifierType).build())
      .build();

    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ImportDefaultSpecifierType)
      .setImportDefaultSpecifier(importDefaultSpecifier)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOf(ESTree.ImportDefaultSpecifier.class);
  }

  @Test
  void should_create_import_specifier_type() {
    ImportSpecifier importSpecifier = ImportSpecifier.newBuilder()
      .setLocal(Node.newBuilder().setType(NodeType.IdentifierType).build())
      .setImported(Node.newBuilder().setType(NodeType.IdentifierType).build())
      .build();

    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ImportSpecifierType)
      .setImportSpecifier(importSpecifier)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOf(ESTree.ImportSpecifier.class);
  }

  @Test
  void should_create_chain_expression_type() {
    CallExpression callExpression = CallExpression.newBuilder()
      .setCallee(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .build();
    Node chainElement = Node.newBuilder()
      .setType(NodeType.CallExpressionType)
      .setCallExpression(callExpression)
      .build();
    ChainExpression chainExpression = ChainExpression.newBuilder()
      .setExpression(chainElement)
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ChainExpressionType)
      .setChainExpression(chainExpression)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.ChainExpression.class, chain -> {
      assertThat(chain.expression()).isInstanceOf(ESTree.CallExpression.class);
    });
  }

  @Test
  void should_create_with_statement_type() {
    WithStatement withStatement = WithStatement.newBuilder()
      .setObject(Node.newBuilder().setType(NodeType.ThisExpressionType).build())
      .setBody(Node.newBuilder().setType(NodeType.BlockStatementType).build())
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.WithStatementType)
      .setWithStatement(withStatement)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.WithStatement.class, with -> {
      assertThat(with.object()).isInstanceOf(ESTree.ThisExpression.class);
      assertThat(with.body()).isInstanceOf(ESTree.BlockStatement.class);
    });
  }

  @Test
  void should_create_empty_statement_type() {
    EmptyStatement emptyStatement = EmptyStatement.newBuilder().build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.EmptyStatementType)
      .setEmptyStatement(emptyStatement)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOf(ESTree.EmptyStatement.class);
  }

  @Test
  void should_create_static_block_type() {
    StaticBlock staticBlock = StaticBlock.newBuilder()
      .addBody(Node.newBuilder().setType(NodeType.EmptyStatementType).build())
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.StaticBlockType)
      .setStaticBlock(staticBlock)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.StaticBlock.class, block -> {
      assertThat(block.body().size()).isEqualTo(1);
      assertThat(block.body().get(0)).isInstanceOf(ESTree.EmptyStatement.class);
    });
  }

  @Test
  void should_create_export_all_declaration_type_using_a_literal() {
    ExportAllDeclaration exportAllDeclaration = ExportAllDeclaration.newBuilder()
      .setExported(
        Node.newBuilder()
          .setType(NodeType.LiteralType)
          .setLiteral(
            Literal.newBuilder()
              .setValueString("4k")
          )
          .build()
      )
      .setSource(
        Node.newBuilder()
          .setType(NodeType.LiteralType)
          .setLiteral(
            Literal.newBuilder()
              .setValueString("yolo")
          )
      )
      .build();

    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ExportAllDeclarationType)
      .setExportAllDeclaration(exportAllDeclaration)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.ExportAllDeclaration.class, declaration -> {
      assertThat(declaration.exported().isPresent()).isTrue();
      var exported = declaration.exported().get();
      assertThat(exported).isInstanceOf(ESTree.Literal.class);
    });
  }

  @Test
  void directive_can_be_in_block_statement() {
    BlockStatement blockStatement = BlockStatement.newBuilder()
      .addBody(Node.newBuilder()
        .setType(NodeType.ExpressionStatementType)
        .setExpressionStatement(ExpressionStatement.newBuilder()
          .setDirective("directiveName")
          .setExpression(Node.newBuilder().setType(NodeType.LiteralType).build())
          .build())
        .build())
      .build();
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.BlockStatementType)
      .setBlockStatement(blockStatement)
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.BlockStatement.class, block -> {
      assertThat(block.body()).hasSize(1);
      assertThat(block.body().get(0)).isInstanceOfSatisfying(ESTree.Directive.class, directive -> {
        assertThat(directive.directive()).isEqualTo("directiveName");
      });
    });
  }

  @Test
  void array_expression_can_contain_empty_elements() {
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ArrayExpressionType)
      .setArrayExpression(ArrayExpression.newBuilder()
        .addElements(ArrayElement.newBuilder().build())
        .addElements(ArrayElement.newBuilder().setElement(Node.newBuilder().setType(NodeType.ThisExpressionType).build()).build())
        .addElements(ArrayElement.newBuilder().build())
        .build())
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.ArrayExpression.class, array -> {
      assertThat(array.elements()).hasSize(3);
      assertThat(array.elements().get(0)).isEmpty();
      assertThat(array.elements().get(1).get()).isInstanceOf(ESTree.ThisExpression.class);
      assertThat(array.elements().get(2)).isEmpty();
    });
  }

  @Test
  void array_pattern_can_contain_empty_elements() {
    Node protobufNode = Node.newBuilder()
      .setType(NodeType.ArrayPatternType)
      .setArrayPattern(ArrayPattern.newBuilder()
        .addElements(ArrayElement.newBuilder().build())
        .addElements(ArrayElement.newBuilder().setElement(Node.newBuilder().setType(NodeType.IdentifierType).build()).build())
        .addElements(ArrayElement.newBuilder().build())
        .build())
      .build();

    ESTree.Node estree = ESTreeFactory.from(protobufNode, ESTree.Node.class);
    assertThat(estree).isInstanceOfSatisfying(ESTree.ArrayPattern.class, array -> {
      assertThat(array.elements()).hasSize(3);
      assertThat(array.elements().get(0)).isEmpty();
      assertThat(array.elements().get(1).get()).isInstanceOf(ESTree.Identifier.class);
      assertThat(array.elements().get(2)).isEmpty();
    });
  }

  @Test
  void throw_exception_from_unrecognized_type() {
    Node protobufNode = Node.newBuilder()
      .setTypeValue(-1)
      .build();

    assertThatThrownBy(() -> ESTreeFactory.from(protobufNode, ESTree.Node.class))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessageStartingWith("Unknown node type: UNRECOGNIZED");
  }

  @Test
  void throw_exception_for_incorrect_cast() {
    Node block = Node.newBuilder()
      .setType(NodeType.BlockStatementType)
      .setBlockStatement(BlockStatement.newBuilder().build())
      .build();

    assertThatThrownBy(() -> ESTreeFactory.from(block, ESTree.Super.class))
      .isInstanceOf(IllegalStateException.class)
      .hasMessage("Expected class org.sonar.plugins.javascript.api.estree.ESTree$Super " +
        "but got class org.sonar.plugins.javascript.api.estree.ESTree$BlockStatement");
  }
}