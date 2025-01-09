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
package org.sonar.plugins.javascript.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.InputFile;

/**
 * An object to assess if a .js file is a minified file or not.
 * <p>
 * An instance of this class is likely to consider as minified a .js file that,
 * although formally not minified, has an unusually high average line length.
 * This situation is typical of files that have been generated by some tool.
 * Such files are of poor interest as regards a SonarQube analysis.
 */
class MinificationAssessor implements Assessor {

  private static final Logger LOG = LoggerFactory.getLogger(MinificationAssessor.class);

  private static final int DEFAULT_AVERAGE_LINE_LENGTH_THRESHOLD = 200;

  /**
   * Value of the average line length
   * (= number of chars in the file / number of lines in the file)
   * below which a file is not assessed as being a minified file.
   */
  private final int averageLineLengthThreshold;

  public MinificationAssessor() {
    this(DEFAULT_AVERAGE_LINE_LENGTH_THRESHOLD);
  }

  public MinificationAssessor(int averageLineLengthThreshold) {
    this.averageLineLengthThreshold = averageLineLengthThreshold;
  }

  public boolean isMinified(InputFile file) {
    return (
      isMinifiableFile(file) && (hasMinifiedFileName(file) || hasExcessiveAverageLineLength(file))
    );
  }

  private static boolean hasMinifiedFileName(InputFile file) {
    String fileName = file.filename();
    return (
      fileName.endsWith("-min.js") ||
      fileName.endsWith(".min.js") ||
      fileName.endsWith("-min.css") ||
      fileName.endsWith(".min.css")
    );
  }

  private static boolean isMinifiableFile(InputFile file) {
    return file.filename().endsWith(".js") || file.filename().endsWith(".css");
  }

  private boolean hasExcessiveAverageLineLength(InputFile file) {
    int averageLineLength = new AverageLineLengthCalculator(file).getAverageLineLength();
    LOG.debug("Average line length for {} is {}", file, averageLineLength);
    return averageLineLength > averageLineLengthThreshold;
  }

  @Override
  public boolean test(InputFile inputFile) {
    return isMinified(inputFile);
  }
}
