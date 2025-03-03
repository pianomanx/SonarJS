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
package org.sonar.plugins.javascript;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.sonar.api.batch.fs.InputFile.Type;
import org.sonar.api.batch.fs.internal.DefaultInputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.rule.CheckFactory;
import org.sonar.api.batch.rule.internal.ActiveRulesBuilder;
import org.sonar.api.batch.rule.internal.NewActiveRule;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.server.rule.RulesDefinition;

public class TestUtils {

  public static DefaultInputFile createInputFile(
    SensorContextTester sensorContext,
    String content,
    String relativePath
  ) {
    DefaultInputFile testInputFile = new TestInputFileBuilder("moduleKey", relativePath)
      .setModuleBaseDir(sensorContext.fileSystem().baseDirPath())
      .setType(Type.MAIN)
      .setLanguage(relativePath.split("\\.")[1])
      .setCharset(StandardCharsets.UTF_8)
      .setContents(content)
      .build();

    sensorContext.fileSystem().add(testInputFile);
    return testInputFile;
  }

  public static DefaultInputFile createInputFile(
    SensorContextTester sensorContext,
    String content,
    String relativePath,
    String language
  ) {
    DefaultInputFile testInputFile = new TestInputFileBuilder("moduleKey", relativePath)
      .setModuleBaseDir(sensorContext.fileSystem().baseDirPath())
      .setType(Type.MAIN)
      .setLanguage(language)
      .setCharset(StandardCharsets.UTF_8)
      .setContents(content)
      .build();

    sensorContext.fileSystem().add(testInputFile);
    return testInputFile;
  }

  public static RulesDefinition.Repository buildRepository(
    String repositoryKey,
    RulesDefinition rulesDefinition
  ) {
    RulesDefinition.Context context = new RulesDefinition.Context();
    rulesDefinition.define(context);
    return context.repository(repositoryKey);
  }

  public static CheckFactory checkFactory(String repositoryKey, String... ruleKeys) {
    return checkFactory(
      Arrays.stream(ruleKeys).map(k -> RuleKey.of(repositoryKey, k)).collect(Collectors.toList())
    );
  }

  public static CheckFactory checkFactory(List<RuleKey> ruleKeys) {
    ActiveRulesBuilder builder = new ActiveRulesBuilder();
    for (var ruleKey : ruleKeys) {
      builder.addRule(new NewActiveRule.Builder().setRuleKey(ruleKey).build());
    }
    return new CheckFactory(builder.build());
  }
}
