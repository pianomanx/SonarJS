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
package org.sonar.javascript.checks;

import java.util.List;
import org.sonar.check.Rule;
import org.sonar.plugins.javascript.api.Check;
import org.sonar.plugins.javascript.api.TypeScriptRule;

@TypeScriptRule
@Rule(key = "S6550")
public class S6550 extends Check {

  @Override
  public List<Object> configurations() {
    return List.of(new Config());
  }

  private static class Config {

    // Option to allow bitwise expressions in enum initializers (Default: false).
    // We might consider changing this flag value if the rule is too noisy.
    // For example, in the ruling, the rule reports +500 issues for the TypeScript project.
    // Remark: Adding a rule property afterward might cause deployment issues with SonarCloud.
    boolean allowBitwiseExpressions = false;
  }
}
