const { bridgeRules } = require('../lib/jsts/src/rules');
const { writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { mkdirpSync } = require('mkdirp');

const targetDir = join(
  __dirname,
  '..',
  'sonar-plugin',
  'sonar-javascript-plugin',
  'target',
  'classes',
);

mkdirpSync(targetDir);
writeFileSync(join(targetDir, 'rules.json'), JSON.stringify(Object.keys(bridgeRules)));
