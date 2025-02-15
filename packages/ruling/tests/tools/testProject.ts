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
import path from 'path';
import fs from 'fs';
import os from 'os';
import { Minimatch } from 'minimatch';
import { accept } from '../filter/JavaScriptExclusionsFilter.js';
import { writeResults } from './lits.js';
import { analyzeHTML } from '../../../html/src/index.js';
import { isHtmlFile, isJsFile, isTsFile, isYamlFile } from './languages.js';
import { analyzeYAML } from '../../../yaml/src/index.js';
import projects from '../data/projects.json' with { type: 'json' };
import { before } from 'node:test';
import { initializeLinter } from '../../../jsts/src/linter/linters.js';
import {
  DEFAULT_ENVIRONMENTS,
  DEFAULT_GLOBALS,
  JsTsFiles,
  ProjectAnalysisInput,
  ProjectAnalysisOutput,
} from '../../../jsts/src/analysis/projectAnalysis/projectAnalysis.js';
import { analyzeProject } from '../../../jsts/src/analysis/projectAnalysis/projectAnalyzer.js';
import { setContext } from '../../../shared/src/helpers/context.js';
import { toUnixPath, FileType } from '../../../shared/src/helpers/files.js';
import { AnalysisInput, AnalysisOutput } from '../../../shared/src/types/analysis.js';
import { RuleConfig } from '../../../jsts/src/linter/config/rule-config.js';

const sourcesPath = path.join(
  import.meta.dirname,
  '..',
  '..',
  '..',
  '..',
  '..',
  'sonarjs-ruling-sources',
);
const jsTsProjectsPath = path.join(sourcesPath, 'jsts', 'projects');

const expectedPath = path.join(
  import.meta.dirname,
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
const actualPath = path.join(import.meta.dirname, '..', 'actual', 'jsts');

const SETTINGS_KEY = 'SONAR_RULING_SETTINGS';
const HTML_LINTER_ID = 'html';

type RulingInput = {
  name: string;
  testDir?: string;
  exclusions?: string;
  folder?: string;
};

const DEFAULT_EXCLUSIONS = [
  '**/.*',
  '**/.*/**',
  '**/*.d.ts',
  '**/node_modules/**',
  '**/bower_components/**',
  '**/dist/**',
  '**/vendor/**',
  '**/external/**',
  '**/contrib/**',
].map(pattern => new Minimatch(pattern, { nocase: true, dot: true }));

export function setupBeforeAll(projectFile: string) {
  const { project, rules, expectedPath, actualPath } = extractParameters(projectFile);

  before(async () => {
    setContext({
      workDir: path.join(os.tmpdir(), 'sonarjs'),
      shouldUseTypeScriptParserForJS: true,
      sonarlint: false,
      bundles: [],
    });
    await initializeRules(rules, project);
  });

  return {
    project,
    expectedPath,
    actualPath,
    rules,
  };
}
async function initializeRules(rules: RuleConfig[], project: RulingInput) {
  await initializeLinter(
    rules,
    DEFAULT_ENVIRONMENTS,
    DEFAULT_GLOBALS,
    path.join(jsTsProjectsPath, project.folder ?? project.name),
  );
  const htmlRules = rules.filter(rule => rule.key !== 'S3504');
  await initializeLinter(
    htmlRules,
    DEFAULT_ENVIRONMENTS,
    DEFAULT_GLOBALS,
    path.join(jsTsProjectsPath, project.folder ?? project.name),
    HTML_LINTER_ID,
  );
}
function getProjectName(testFilePath: string) {
  const SUFFIX = '.ruling.test.ts';
  const filename = path.basename(testFilePath);
  return filename.substring(0, filename.length - SUFFIX.length);
}
function extractParameters(projectFile: string) {
  const settingsPath = process.env[SETTINGS_KEY];
  let params;
  if (settingsPath) {
    params = extractSettingsFromFile(settingsPath);
  }
  const projectName = getProjectName(toUnixPath(projectFile));
  const project = projects.find(p => p.name === projectName);

  return {
    project,
    rules: params?.rules || loadRules(),
    expectedPath: params?.expectedPath
      ? path.join(params?.expectedPath, project.name)
      : path.join(expectedPath, project.name),
    actualPath: params?.actualPath
      ? path.join(params?.actualPath, project.name)
      : path.join(actualPath, project.name),
  };
}
function extractSettingsFromFile(pathToSettings: string) {
  return require(pathToSettings);
}

/**
 * Load files and analyze project
 */
export async function testProject(
  rulingInput: RulingInput,
  actualPath: string,
  rules: RuleConfig[],
) {
  const projectPath = path.join(jsTsProjectsPath, rulingInput.folder ?? rulingInput.name);
  const exclusions = setExclusions(rulingInput.exclusions, rulingInput.testDir);

  const { jsTsFiles, htmlFiles, yamlFiles } = getProjectFiles(rulingInput, projectPath, exclusions);

  const payload: ProjectAnalysisInput = {
    rules,
    baseDir: projectPath,
    files: jsTsFiles,
  };

  const jsTsResults = await analyzeProject(payload);
  const htmlResults = await analyzeFiles(htmlFiles, analyzeHTML, HTML_LINTER_ID);
  const yamlResults = await analyzeFiles(yamlFiles, analyzeYAML);
  const results = mergeResults(jsTsResults, htmlResults, yamlResults);

  writeResults(
    projectPath,
    rulingInput.name,
    results,
    [jsTsFiles, htmlFiles, yamlFiles],
    actualPath,
  );
}

/**
 * Creates the exclusions object
 */
function setExclusions(exclusions: string, testDir?: string) {
  const exclusionsArray = exclusions ? exclusions.split(',') : [];
  if (testDir && testDir !== '') {
    exclusionsArray.push(...testDir.split(',').map(dir => `${dir}/**/*`));
  }
  const exclusionsGlob = stringToGlob(exclusionsArray.map(pattern => pattern.trim()));
  return exclusionsGlob;

  function stringToGlob(patterns: string[]): Minimatch[] {
    return patterns.map(pattern => new Minimatch(pattern, { nocase: true, matchBase: true }));
  }
}

/**
 * Gathers all the files that should be analyzed for the given project
 */
function getProjectFiles(rulingInput: RulingInput, projectPath: string, exclusions: Minimatch[]) {
  const { jsTsFiles, htmlFiles, yamlFiles } = getFiles(projectPath, exclusions);

  if (rulingInput.testDir != null) {
    const testFolder = path.join(projectPath, rulingInput.testDir);
    getFiles(testFolder, exclusions, jsTsFiles, htmlFiles, yamlFiles, 'TEST');
  }
  return { jsTsFiles, htmlFiles, yamlFiles };
}

/**
 * Stores in `jsTsFiles`, `htmlFiles` and `yamlFiles` the files
 * found in the given `dir`, ignoring the given `exclusions` and
 * assigning the given `type`
 */
function getFiles(
  dir: string,
  exclusions: Minimatch[],
  jsTsFiles: JsTsFiles = {},
  htmlFiles: JsTsFiles = {},
  yamlFiles: JsTsFiles = {},
  type: FileType = 'MAIN',
) {
  const prefixLength = toUnixPath(dir).length + 1;
  const files = fs.readdirSync(dir, { recursive: true, withFileTypes: true });
  for (const file of files) {
    const absolutePath = toUnixPath(path.join(file.path, file.name));
    const relativePath = absolutePath.substring(prefixLength);
    if (!file.isFile()) continue;
    if (isExcluded(relativePath, exclusions)) continue;
    if (isExcluded(absolutePath, DEFAULT_EXCLUSIONS)) continue;
    const fileContent = fs.readFileSync(absolutePath, 'utf8');
    const language = findLanguage(absolutePath, fileContent);
    if (!language) continue;

    if (isHtmlFile(absolutePath)) {
      htmlFiles[absolutePath] = { fileType: type, fileContent, language };
    } else if (isYamlFile(absolutePath)) {
      yamlFiles[absolutePath] = { fileType: type, fileContent, language };
    } else {
      if (!accept(absolutePath, fileContent)) continue;
      jsTsFiles[absolutePath] = { fileType: type, fileContent, language };
    }
  }
  return { jsTsFiles, htmlFiles, yamlFiles };
}

function findLanguage(filePath: string, contents: string) {
  if (isTsFile(filePath, contents)) {
    return 'ts';
  }
  if (isJsFile(filePath)) {
    return 'js';
  }
}

function isExcluded(filePath: string, exclusions: Minimatch[]) {
  return exclusions.some(exclusion => exclusion.match(filePath));
}

/**
 * Analyze files the old school way.
 * Used for HTML and YAML
 */
async function analyzeFiles(
  files: JsTsFiles,
  analyzer: (payload: AnalysisInput) => Promise<AnalysisOutput>,
  linterId?: string,
) {
  const results = { files: {} };
  for (const [filePath, fileData] of Object.entries(files)) {
    const payload: AnalysisInput = {
      filePath,
      fileContent: fileData.fileContent,
      linterId,
    };
    try {
      const result = await analyzer(payload);
      results.files[filePath] = result;
    } catch (err) {
      results.files[filePath] = createParsingIssue(err);
    }
    results.files[filePath].language = fileData.language;
  }
  return results;
}

/**
 * Merge results from multiple analyses into a single object
 * Creates parsing issues from parsingError when needed
 */
function mergeResults(...resultsSet: ProjectAnalysisOutput[]) {
  const allResults = { files: {} };
  for (const results of resultsSet) {
    for (const [filePath, fileData] of Object.entries(results.files)) {
      if (allResults.files[filePath]) {
        throw Error(`File ${filePath} has been analyzed in multiple paths`);
      }
      if (fileData.parsingError) {
        allResults.files[filePath] = createParsingIssue({ data: fileData.parsingError });
      } else {
        allResults.files[filePath] = fileData;
      }
    }
  }
  return allResults;
}

/**
 * Creates a S2260 issue for the parsing error
 */
function createParsingIssue({
  data: { line, message },
}: {
  data: { line?: number; message: string };
}) {
  return {
    issues: [
      {
        ruleId: 'S2260',
        line,
        // stub values so we don't have to modify the type
        message,
        column: 0,
        secondaryLocations: [],
      },
    ],
  };
}

/**
 * Loading this through `fs` and not import because the file is absent at compile time
 */
function loadRules() {
  const rulesPath = path.join(import.meta.dirname, '..', 'data', 'rules.json');
  const rulesContent = fs.readFileSync(rulesPath, 'utf8');
  return JSON.parse(rulesContent);
}
