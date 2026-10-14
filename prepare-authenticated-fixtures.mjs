import fs from 'node:fs';
import path from 'node:path';

if (process.env.GITHUB_REPOSITORY !== 'AbdulrahmanFa2hy/menu-delight-load-testing' ||
    process.env.GITHUB_REF !== 'refs/heads/codex/authenticated-transport-diagnostics' || process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch')
  throw new Error('Authenticated diagnostics require the approved repository, branch and manual dispatch');
const fixtures = JSON.parse(fs.readFileSync('tracking-experiences.json', 'utf8'));
if (fixtures.length !== 10 || !process.env.RUNNER_TEMP) throw new Error('Missing fixture configuration');
const configured = fixtures.map((fixture, index) => {
  const token = process.env[`TRACKING_TOKEN_${index + 1}`];
  if (!token || token.length < 32 || /[\r\n]/.test(token)) throw new Error('Missing fixture token');
  console.log(`::add-mask::${token}`);
  return {...fixture, token};
});
const file = path.join(process.env.RUNNER_TEMP, 'authenticated-private-fixtures.json');
fs.writeFileSync(file, JSON.stringify(configured), {mode: 0o600, flag: 'wx'});
fs.appendFileSync(process.env.GITHUB_ENV, `FIXTURE_FILE=${file}\n`);
