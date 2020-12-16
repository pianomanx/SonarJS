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
package org.sonar.javascript.tree.impl.statement;

import org.junit.Test;
import org.sonar.javascript.lexer.JavaScriptKeyword;
import org.sonar.javascript.utils.JavaScriptTreeModelTest;
import org.sonar.plugins.javascript.api.tree.Tree.Kind;
import org.sonar.plugins.javascript.api.tree.statement.ReturnStatementTree;

import static org.assertj.core.api.Assertions.assertThat;

public class ReturnStatementTreeModelTest extends JavaScriptTreeModelTest {

  @Test
  public void with_expression() throws Exception {
    ReturnStatementTree tree = parse("return expr ;", Kind.RETURN_STATEMENT);

    assertThat(tree.is(Kind.RETURN_STATEMENT)).isTrue();
    assertThat(tree.returnKeyword().text()).isEqualTo(JavaScriptKeyword.RETURN.getValue());
    assertThat(tree.expression()).isNotNull();
    assertThat(tree.semicolonToken()).isNotNull();
  }

  @Test
  public void without_expression() throws Exception {
    ReturnStatementTree tree = parse("return ;", Kind.RETURN_STATEMENT);

    assertThat(tree.is(Kind.RETURN_STATEMENT)).isTrue();
    assertThat(tree.returnKeyword().text()).isEqualTo(JavaScriptKeyword.RETURN.getValue());
    assertThat(tree.expression()).isNull();
    assertThat(tree.semicolonToken()).isNotNull();
  }

}