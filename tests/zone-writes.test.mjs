import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { zoneTasks } from '../scripts/zone-journey.mjs';

for (const task of [...zoneTasks, 'B3.OP-049', 'B3.OP-051', 'B3.OP-052']) {
  test(`${task} packaged native operation succeeds offline and preserves unrelated data`, { timeout: 180000 }, () => {
    const result = spawnSync(process.execPath, [new URL('../scripts/journey.mjs', import.meta.url).pathname,
      '--task', task, '--paths', 'native', '--offline'], { encoding: 'utf8', timeout: 175000 });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.failed, 0);
    assert.equal(report.actual, report.expected);
  });
}
