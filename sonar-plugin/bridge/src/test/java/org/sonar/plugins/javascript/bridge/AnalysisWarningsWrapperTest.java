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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class AnalysisWarningsWrapperTest {

  @Test
  void test() {
    List<String> warnings = new ArrayList<>();
    AnalysisWarningsWrapper wrapper = new AnalysisWarningsWrapper(warnings::add);
    wrapper.addUnique("test");
    assertThat(warnings).containsExactly("test");
  }

  @Test
  void test_null() {
    try {
      AnalysisWarningsWrapper wrapper = new AnalysisWarningsWrapper(null);
      wrapper.addUnique("test");
    } catch (Exception e) {
      fail("No exception should be thrown");
    }
  }
}
