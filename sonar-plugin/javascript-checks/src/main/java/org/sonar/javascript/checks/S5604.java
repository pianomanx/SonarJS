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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.sonar.check.Rule;
import org.sonar.check.RuleProperty;
import org.sonar.plugins.javascript.api.Check;
import org.sonar.plugins.javascript.api.JavaScriptRule;
import org.sonar.plugins.javascript.api.TypeScriptRule;

@JavaScriptRule
@TypeScriptRule
@Rule(key = "S5604")
public class S5604 extends Check {

  private static final String DEFAULT = "geolocation";

  @RuleProperty(
    key = "permissions",
    description = "Comma-separated list of intrusive permissions to report " +
    "(supported values: geolocation, camera, microphone, notifications, persistent-storage)",
    defaultValue = "" + DEFAULT
  )
  public String permissions = DEFAULT;

  @Override
  public List<Object> configurations() {
    return Collections.singletonList(
      new Config(Arrays.stream(permissions.split(",")).map(String::trim).toArray(String[]::new))
    );
  }

  private static class Config {

    String[] permissions;

    Config(String[] permissions) {
      this.permissions = permissions;
    }
  }
}
