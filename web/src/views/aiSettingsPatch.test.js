import assert from 'node:assert/strict';
import { test } from 'node:test';
import { changedAiSettings } from './aiSettingsPatch.js';

test('an unrelated save does not overwrite a newer active threshold', () => {
  const saved = { workers: 2, block_threshold: 0.99, authority: { enabled: false } };
  const edited = { workers: 3, block_threshold: 0.99, authority: { enabled: false } };
  const live = { ...saved, block_threshold: 0.94 };

  const patch = changedAiSettings(saved, edited);
  assert.deepEqual(patch, { workers: 3 });
  assert.equal({ ...live, ...patch }.block_threshold, 0.94);
});

test('explicit threshold and authority changes are included', () => {
  const saved = { block_threshold: 0.99, authority: { enabled: false, model_stage: 'propose' } };
  const edited = { block_threshold: 0.95, authority: { enabled: true, model_stage: 'propose' } };
  assert.deepEqual(changedAiSettings(saved, edited), edited);
});
