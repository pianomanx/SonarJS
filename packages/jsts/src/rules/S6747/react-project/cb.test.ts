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
import { check } from '../../../../tests/tools/index.js';
import { rule } from '../index.js';
import path from 'path';
import { describe } from 'node:test';

const sonarId = path.basename(import.meta.dirname);

describe('Rule S6747', () => {
  process.chdir(import.meta.dirname); // change current working dir to avoid the package.json lookup to up in the tree
  check(sonarId, rule, import.meta.dirname);
});
