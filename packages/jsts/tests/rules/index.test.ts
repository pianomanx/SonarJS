/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2024 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

import { configs, rules, meta } from '../../src/rules/plugin.js';
import fs from 'fs';
import path from 'path';
import { valid } from 'semver';
import { describe, it } from 'node:test';
import { expect } from 'expect';
import { pathToFileURL } from 'node:url';

const mappedRules = new Map(
  Object.entries(rules).map(([eslintId, rule]) => [rule.meta.docs.url, eslintId]),
);

describe('Plugin public API', () => {
  it('should map keys to rules definitions', async () => {
    const ruleFolder = path.join(import.meta.dirname, '../../src/rules');
    const sonarKeys = fs.readdirSync(ruleFolder).filter(name => /^S\d+/.test(name));
    const missing = [];
    for (const sonarKey of sonarKeys) {
      const { rule } = await import(
        pathToFileURL(path.join(ruleFolder, sonarKey, 'index.js')).toString()
      );
      expect(rule.meta.docs!.url).toBe(
        `https://sonarsource.github.io/rspec/#/rspec/${sonarKey}/javascript`,
      );
      const { meta } = await import(
        pathToFileURL(path.join(ruleFolder, sonarKey, 'meta.js')).toString()
      );
      const eslintId = mappedRules.get(rule.meta.docs.url);
      if (!eslintId) {
        missing.push(sonarKey);
      } else {
        if (meta.docs.recommended) {
          expect(configs.recommended.rules).toHaveProperty(`sonarjs/${eslintId}`);
          expect(configs.recommended.rules[`sonarjs/${eslintId}`]).toEqual('error');
        } else {
          expect(configs.recommended.rules[`sonarjs/${eslintId}`]).toEqual('off');
        }
        expect(configs.recommended.plugins!['sonarjs'].rules).toHaveProperty(eslintId);
      }
    }
    expect(missing).toHaveLength(0);
  });

  it('should export legacy config', () => {
    const legacyConfig = configs['recommended-legacy'];
    expect(legacyConfig.plugins).toEqual(['sonarjs']);
    expect(legacyConfig.rules).toEqual(configs.recommended.rules);
    expect(legacyConfig.settings).toEqual(configs.recommended.settings);
  });

  it('should export meta', () => {
    expect(meta.name).toEqual('eslint-plugin-sonarjs');
    expect(valid(meta.version)).toBeTruthy();
  });
});
