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
import { join, basename } from 'node:path/posix';
import { writeResults } from './lits.js';
import projects from '../data/projects.json' with { type: 'json' };
import { analyzeProject } from '../../../jsts/src/analysis/projectAnalysis/projectAnalyzer.js';
import { toUnixPath } from '../../../shared/src/helpers/files.js';
import { compare, Result } from 'dir-compare';
import { RuleConfig } from '../../../jsts/src/linter/config/rule-config.js';
import { expect } from 'expect';
import * as metas from '../../../jsts/src/rules/metas.js';
import { SonarMeta } from '../../../jsts/src/rules/index.js';
import { defaultOptions } from '../../../jsts/src/rules/helpers/configs.js';

const currentPath = toUnixPath(import.meta.dirname);

const sourcesPath = join(currentPath, '..', '..', '..', '..', '..', 'sonarjs-ruling-sources');
const jsTsProjectsPath = join(sourcesPath, 'jsts', 'projects');
const expectedPathBase = join(
  currentPath,
  '..',
  '..',
  '..',
  '..',
  'its',
  'ruling',
  'src',
  'test',
  'expected',
  'jsts',
);
const actualPathBase = join(currentPath, '..', 'actual', 'jsts');

const SETTINGS_KEY = 'SONAR_RULING_SETTINGS';

type ProjectsData = {
  name: string;
  folder: string;
  testDir: string;
  exclusions: string;
};

export function projectName(projectFile: string) {
  const filename = basename(toUnixPath(projectFile));
  return filename.substring(0, filename.length - '.ruling.test.ts'.length);
}

export async function testProject(projectName: string) {
  const settingsPath = process.env[SETTINGS_KEY];
  let params: {
    rules?: RuleConfig[];
    expectedPath?: string;
    actualPath?: string;
  } = {};
  if (settingsPath) {
    params = require(settingsPath);
  }

  const { folder, name, exclusions, testDir } = (projects as ProjectsData[]).find(
    p => p.name === projectName,
  );
  const rules = Object.entries(metas)
    .flatMap(([key, meta]: [string, SonarMeta]): RuleConfig[] => {
      return meta.languages.map(language => ({
        key,
        configurations: defaultOptions(meta.fields) || [],
        language: language === 'JAVASCRIPT' ? 'js' : 'ts',
        fileTypeTargets: meta.scope === 'Tests' ? ['TEST'] : ['MAIN'],
        analysisModes: ['DEFAULT'],
        blacklistedExtensions: meta.blacklistedExtensions,
      }));
    })
    .map(applyRulingConfig);
  const expectedPath = join(params?.expectedPath ?? expectedPathBase, name);
  const actualPath = join(params?.actualPath ?? actualPathBase, name);

  const baseDir = join(jsTsProjectsPath, folder ?? name);

  const results = await analyzeProject({
    rules,
    baseDir,
    configuration: {
      tests: testDir ? [testDir] : undefined,
      jsTsExclusions: exclusions?.split(','),
    },
  });

  await writeResults(baseDir, name, results, actualPath);

  return await compare(expectedPath, actualPath, { compareContent: true });
}

export function ok(diff: Result) {
  expect(
    JSON.stringify(
      diff.diffSet.filter(value => value.state !== 'equal'),
      null,
      2,
    ),
  ).toEqual('[]');
}

/**
 * Apply the non-default configuration for some rules
 */
function applyRulingConfig(rule: RuleConfig) {
  switch (rule.key) {
    case 'S2486': {
      // for some reason the scope is different
      rule.fileTypeTargets = ['TEST'];
      break;
    }
    case 'S1451': {
      if (rule.language === 'js') {
        rule.configurations[0].headerFormat =
          '// Copyright 20\\d\\d The Closure Library Authors. All Rights Reserved.';
        rule.configurations[0].isRegularExpression = true;
      } else {
        rule.configurations[0].headerFormat = '//.*';
        rule.configurations[0].isRegularExpression = true;
      }
      break;
    }
    case 'S124': {
      rule.configurations[0].regularExpression = '.*TODO.*';
      rule.configurations[0].flags = 'i';
      break;
    }
    case 'S1192': {
      if (rule.language === 'js') {
        rule.configurations[0]!.threshold = 4;
      }
      break;
    }
  }
  return rule;
}
