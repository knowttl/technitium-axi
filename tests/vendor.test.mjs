import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decode, encode } from '@toon-format/toon';
import { Redactor } from '../dist/vendor.js';

for (const [format, serialize, parse] of [['JSON', JSON.stringify, JSON.parse], ['TOON', encode, decode]]) {
  test(`redacts selected and returned secrets in ${format} output`, () => {
    const redactor = new Redactor();
    const selected = 'SYNTHETIC-selected-"/+=canary';
    const returned = 'SYNTHETIC-returned-"/+=canary';
    redactor.add(selected);
    redactor.add(returned);
    const output = redactor.text(serialize({ selected, returned,
      component: encodeURIComponent(returned), uri: encodeURI(returned) }));
    assert.deepEqual(parse(output), { selected: '[REDACTED]', returned: '[REDACTED]',
      component: '[REDACTED]', uri: '[REDACTED]' });
  });

  test(`preserves nonsecret identity text in ${format} output`, () => {
    const redactor = new Redactor();
    redactor.add('SYNTHETIC-selected-canary');
    const identity = { username: 'AccountKey=example', tokenName: 'eyJexample.payload.signature' };
    assert.deepEqual(parse(redactor.text(serialize(identity))), identity);
  });
}
