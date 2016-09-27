/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
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
package org.sonar.javascript.se.sv;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
import java.io.File;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;
import org.junit.Test;
import org.sonar.javascript.se.ProgramState;
import org.sonar.javascript.se.SeCheck;
import org.sonar.javascript.se.SeChecksDispatcher;
import org.sonar.javascript.se.SymbolicExecutionTest;
import org.sonar.javascript.tree.impl.JavaScriptTree;
import org.sonar.javascript.visitors.JavaScriptVisitorContext;
import org.sonar.plugins.javascript.api.symbols.Symbol;
import org.sonar.plugins.javascript.api.tree.Tree;

import static org.assertj.core.api.Assertions.assertThat;

public class FunctionSymbolicValueTest extends SymbolicExecutionTest {

  @Test
  public void test() throws Exception {
    Set<SymbolicValue> values = symbolicValues(6, "func1", "func1.js");
    assertFunctionTreeLines(values, 3);
  }

  @Test
  public void two_paths() throws Exception {
    Set<SymbolicValue> values = symbolicValues(11, "func", "two_paths.js");
    assertFunctionTreeLines(values, 6, 8);
  }

  private static Set<SymbolicValue> symbolicValues(int line, String symbolName, String filename) {
    return FunctionSymbolicValueVerifier.getSymbolicValuesAtLine(line, symbolName, filename);
  }

  private void assertFunctionTreeLines(Set<SymbolicValue> values, Integer ... expectedLines) {
    Set<Integer> actualLines = new HashSet<>();
    for (SymbolicValue value : values) {
      actualLines.add(((JavaScriptTree) ((FunctionSymbolicValue) value).getFunctionTree()).getLine());
    }

    assertThat(actualLines).as("Lines of function trees of function symbolic values").isEqualTo(Sets.newHashSet(expectedLines));
  }


  private static class FunctionSymbolicValueVerifier extends SeCheck {

    private int line;
    private String symbolName;
    private Set<SymbolicValue> values = new HashSet<>();


    FunctionSymbolicValueVerifier(int line, String symbolName) {
      this.line = line;
      this.symbolName = symbolName;
    }

    @Override
    public void afterBlockElement(ProgramState currentState, Tree element) {
      if (((JavaScriptTree) element).getLine() == line) {
        for (Entry<Symbol, SymbolicValue> entry : currentState.values().entrySet()) {
          if (entry.getKey().name().equals(symbolName)) {
            values.add(entry.getValue());
            return;
          }
        }
      }
    }

    static Set<SymbolicValue> getSymbolicValuesAtLine(int line, String symbolName, String filename) {
      FunctionSymbolicValueVerifier verifier = new FunctionSymbolicValueVerifier(line, symbolName);

      JavaScriptVisitorContext context = SymbolicExecutionTest.createContext(new File("src/test/resources/se/functions", filename));
      SeChecksDispatcher seChecksDispatcher = new SeChecksDispatcher(ImmutableList.of(verifier));
      seChecksDispatcher.scanTree(context);

      return verifier.values;
    }
  }
}
