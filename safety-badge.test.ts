import assert from 'node:assert/strict';
import { safetyBadgeSvg } from './src/safetyBadgeVisual.ts';

const seed = '0123456789abcdef'.repeat(4);
const sameA = safetyBadgeSvg(seed, 240);
const sameB = safetyBadgeSvg(seed, 240);
const changed = safetyBadgeSvg('fedcba9876543210'.repeat(4), 240);

assert.equal(sameA, sameB, '相同 256-bit 种子必须生成逐字节一致的视觉徽章');
assert.notEqual(sameA, changed, '种子变化必须生成不同的视觉徽章');
assert.match(sameA, /^<svg\b/u, '输出必须是 SVG');
assert.doesNotMatch(sameA, /<script|foreignObject|\son\w+=/iu, '视觉徽章不得包含可执行 SVG 内容');

console.log('safety badge tests passed');
