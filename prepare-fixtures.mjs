import fs from 'node:fs';
import path from 'node:path';

if (process.env.GITHUB_REF !== 'refs/heads/main') throw new Error('Benchmarks run only from reviewed main');
const fixtures = JSON.parse(fs.readFileSync('tracking-experiences.json', 'utf8'));
if (fixtures.length !== 10) throw new Error('Expected ten benchmark fixtures');
const configured = fixtures.map((fixture, index) => {
  const token = process.env[`TRACKING_TOKEN_${index + 1}`];
  if (!token || token.length < 32 || /[\r\n]/.test(token)) throw new Error('Missing fixture token');
  console.log(`::add-mask::${token}`);
  return { ...fixture, token };
});
const file = path.join(process.env.RUNNER_TEMP, 'benchmark-private-fixtures.json');
fs.writeFileSync(file, JSON.stringify(configured), { mode: 0o600 });
fs.appendFileSync(process.env.GITHUB_ENV, `FIXTURE_FILE=${file}\n`);
