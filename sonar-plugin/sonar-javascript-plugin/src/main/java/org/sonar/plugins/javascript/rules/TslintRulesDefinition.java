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
package org.sonar.plugins.javascript.rules;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.plugins.javascript.TypeScriptLanguage;
import org.sonarsource.analyzer.commons.ExternalRuleLoader;

public class TslintRulesDefinition implements RulesDefinition {

  public static final String REPOSITORY_KEY = "tslint_repo";
  public static final String LINTER_NAME = "TSLint";

  private static final String TSLINT_JSON_CLASSPATH =
    "org/sonar/l10n/typescript/rules/tslint/rules.json";
  private static final String TSLINT_SONARTS_JSON_CLASSPATH =
    "org/sonar/l10n/typescript/rules/tslint-sonarts/rules.json";

  private static final List<ExternalRuleLoader> RULE_LOADERS = Arrays.asList(
    new ExternalRuleLoader(
      REPOSITORY_KEY,
      LINTER_NAME,
      TSLINT_JSON_CLASSPATH,
      TypeScriptLanguage.KEY
    ),
    new ExternalRuleLoader(
      REPOSITORY_KEY,
      "tslint-sonarts",
      TSLINT_SONARTS_JSON_CLASSPATH,
      TypeScriptLanguage.KEY
    )
  );

  private static final Map<String, RuleType> RULE_TYPE_MAP = RULE_LOADERS.stream()
    .flatMap(loader ->
      loader
        .ruleKeys()
        .stream()
        .collect(Collectors.toMap(Function.identity(), loader::ruleType))
        .entrySet()
        .stream()
    )
    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

  @Override
  public void define(Context context) {
    RULE_LOADERS.forEach(ruleLoader -> ruleLoader.createExternalRuleRepository(context));
  }

  public static RuleType ruleType(String ruleKey) {
    return RULE_TYPE_MAP.getOrDefault(ruleKey, RuleType.CODE_SMELL);
  }
}
