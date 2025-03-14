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
package org.sonar.plugins.javascript.bridge;

import static org.sonarsource.api.sonarlint.SonarLintSide.INSTANCE;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.stream.Stream;
import org.sonar.api.config.Configuration;
import org.sonar.api.scanner.ScannerSide;
import org.sonarsource.api.sonarlint.SonarLintSide;

/**
 * Class to access host parameters.
 * This abstraction is necessary to mock it in tests.
 */
@ScannerSide
@SonarLintSide(lifespan = INSTANCE)
public class Environment {

  private final Configuration configuration;

  public Environment(Configuration configuration) {
    this.configuration = configuration;
  }

  public Path getSonarUserHome() {
    return Stream.of(
      configuration.get("sonar.userHome").orElse(null),
      System.getenv("SONAR_USER_HOME"),
      defaultSonarUserHome()
    )
      .filter(Objects::nonNull)
      .findFirst()
      .map(Path::of)
      .get();
  }

  public static String defaultSonarUserHome() {
    return System.getProperty("user.home") + File.separator + ".sonar";
  }

  public String getOsName() {
    return System.getProperty("os.name");
  }

  public String getOsArch() {
    return System.getProperty("os.arch");
  }

  public boolean isAlpine() {
    return Files.exists(Path.of("/etc/alpine-release"));
  }
}
