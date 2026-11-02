import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { appsRestoreTasks } from '../scripts/apps-restore-journey.mjs';

for (const task of appsRestoreTasks) {
  test(`${task} packaged native behavior and failure handling`, { timeout: 180000 }, () => {
    const result = spawnSync(process.execPath, [new URL('../scripts/journey.mjs', import.meta.url).pathname,
      '--task', task, '--paths', 'native', '--offline'], { encoding: 'utf8', timeout: 175000 });
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
}
