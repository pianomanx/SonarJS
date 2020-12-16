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
package org.sonar.javascript.parser.expressions;

import org.junit.Test;
import org.sonar.plugins.javascript.api.tree.Tree.Kind;

import static org.sonar.javascript.utils.Assertions.assertThat;

public class ObjectAssignmentPatternTest {

  @Test
  public void test() {
    assertThat(Kind.OBJECT_ASSIGNMENT_PATTERN)
      .matches("{ }")
      .matches("{ identifierRef , }")
      .matches("{ identifierRef , identifierRef}")
      .matches("{ identifierRef , identifierRef, }")
      .matches("{ identifierRef = init() }")
      .matches("{ identifierName : foo }")
      .matches("{ identifierName : foo.bar }")
      .matches("{ identifierName : foo = init() }")
    ;
  }

}