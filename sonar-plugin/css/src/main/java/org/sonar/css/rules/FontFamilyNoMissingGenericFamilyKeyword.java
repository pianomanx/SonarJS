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
package org.sonar.css.rules;

import static org.sonar.css.rules.RuleUtils.splitAndTrim;

import java.util.Arrays;
import java.util.List;
import org.sonar.check.Rule;
import org.sonar.check.RuleProperty;

@Rule(key = "S4649")
public class FontFamilyNoMissingGenericFamilyKeyword implements CssRule {

  private static final String DEFAULT_IGNORE_FONT_FAMILIES = "";

  @RuleProperty(
    key = "ignoreFontFamilies",
    description = "Comma-separated list of font families to ignore. Each value can be a string or a regular expression with the syntax /pattern/.",
    defaultValue = "" + DEFAULT_IGNORE_FONT_FAMILIES
  )
  String ignoreFontFamilies = DEFAULT_IGNORE_FONT_FAMILIES;

  @Override
  public String stylelintKey() {
    return "font-family-no-missing-generic-family-keyword";
  }

  @Override
  public List<Object> stylelintOptions() {
    return Arrays.asList(true, new StylelintIgnoreOption(splitAndTrim(ignoreFontFamilies)));
  }

  private static class StylelintIgnoreOption {

    // Used by GSON serialization
    private final List<String> ignoreFontFamilies;

    StylelintIgnoreOption(List<String> ignoreFontFamilies) {
      this.ignoreFontFamilies = ignoreFontFamilies;
    }
  }
}
