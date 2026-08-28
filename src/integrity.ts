import { blake2b } from '@noble/hashes/blake2.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { md5, sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';

export type StreamingHasher = {
  update(data: Uint8Array): unknown;
  digest(): Uint8Array;
};

export type AlgorithmId =
  | 'MD5'
  | 'SHA-1'
  | 'SHA-256'
  | 'SHA-512'
  | 'SHA3-256'
  | 'SHA3-512'
  | 'BLAKE2b-512'
  | 'BLAKE3';

export type AlgorithmSpec = {
  id: AlgorithmId;
  bits: number;
  hexLength: number;
  note: string;
  create: () => StreamingHasher;
};

export const ALGORITHM_SPECS: readonly AlgorithmSpec[] = [
  { id: 'MD5', bits: 128, hexLength: 32, note: '仅用于兼容旧清单，不具抗碰撞安全性', create: () => md5.create() },
  { id: 'SHA-1', bits: 160, hexLength: 40, note: 'Git 等旧系统常用，不建议用于安全校验', create: () => sha1.create() },
  { id: 'SHA-256', bits: 256, hexLength: 64, note: '应用最广的安全哈希标准', create: () => sha256.create() },
  { id: 'SHA-512', bits: 512, hexLength: 128, note: '高强度哈希，64 位平台上吞吐很高', create: () => sha512.create() },
  { id: 'SHA3-256', bits: 256, hexLength: 64, note: 'NIST 最新一代哈希标准', create: () => sha3_256.create() },
  { id: 'SHA3-512', bits: 512, hexLength: 128, note: 'NIST 最新一代哈希标准', create: () => sha3_512.create() },
  { id: 'BLAKE2b-512', bits: 512, hexLength: 128, note: '高速安全哈希，兼容 b2sum 等旧清单', create: () => blake2b.create({ dkLen: 64 }) },
  { id: 'BLAKE3', bits: 256, hexLength: 64, note: '当前最快的安全哈希，本工具默认算法', create: () => blake3.create({ dkLen: 32 }) },
];

export const DEFAULT_ALGORITHMS: readonly AlgorithmId[] = ['BLAKE3'];

const SPEC_BY_ID = new Map<string, AlgorithmSpec>(ALGORITHM_SPECS.map((spec) => [spec.id, spec]));

export function isAlgorithmId(value: unknown): value is AlgorithmId {
  return typeof value === 'string' && SPEC_BY_ID.has(value);
}

export function algorithmSpec(id: AlgorithmId): AlgorithmSpec {
  return SPEC_BY_ID.get(id)!;
}

export function algorithmsByHexLength(hexLength: number): AlgorithmId[] {
  return ALGORITHM_SPECS.filter((spec) => spec.hexLength === hexLength).map((spec) => spec.id);
}

export function normalizeAlgorithms(value: unknown): AlgorithmId[] {
  if (!Array.isArray(value)) return [];
  const ids = value.filter(isAlgorithmId);
  return ALGORITHM_SPECS.map((spec) => spec.id).filter((id) => ids.includes(id));
}

export type ManifestEntry = {
  path: string;
  size?: number;
  hashes: Partial<Record<AlgorithmId, string>>;
  /**
   * A structured JSON entry is one `all` group.  An unlabeled GNU line is an
   * `any` group because a digest length can identify more than one algorithm.
   * Keeping groups separate prevents those two meanings from being confused
   * when a text manifest contains more than one record for a path.
   */
  expectations?: ManifestHashExpectation[];
};

export type ManifestHashExpectation = {
  mode: 'all' | 'any';
  hashes: Partial<Record<AlgorithmId, string>>;
};

export type IntegrityManifest = {
  algorithms: AlgorithmId[];
  createdAt?: string;
  files: ManifestEntry[];
};

const BSD_ALIASES = new Map<string, AlgorithmId>(
  [
    ['MD5', 'MD5'],
    ['SHA1', 'SHA-1'],
    ['SHA-1', 'SHA-1'],
    ['SHA256', 'SHA-256'],
    ['SHA-256', 'SHA-256'],
    ['SHA512', 'SHA-512'],
    ['SHA-512', 'SHA-512'],
    ['SHA3-256', 'SHA3-256'],
    ['SHA3-512', 'SHA3-512'],
    ['BLAKE2B', 'BLAKE2b-512'],
    ['BLAKE2B-512', 'BLAKE2b-512'],
    ['BLAKE3', 'BLAKE3'],
  ],
);

function collectAlgorithms(files: ManifestEntry[]): AlgorithmId[] {
  const used = new Set<AlgorithmId>();
  for (const entry of files) {
    for (const id of Object.keys(entry.hashes) as AlgorithmId[]) used.add(id);
  }
  return ALGORITHM_SPECS.map((spec) => spec.id).filter((id) => used.has(id));
}

function validDigest(value: unknown, id: AlgorithmId): value is string {
  return typeof value === 'string' && value.length === algorithmSpec(id).hexLength && /^[0-9a-f]+$/iu.test(value);
}

function parseJsonManifest(parsed: unknown): IntegrityManifest | null {
  if (!parsed || typeof parsed !== 'object') return null;
  const record = parsed as Record<string, unknown>;

  if (record.format === 'CRYPTA-BLAKE2B' && record.version === 1) {
    const files = Array.isArray(record.files) ? record.files : [];
    const entries: ManifestEntry[] = [];
    for (const item of files) {
      if (!item || typeof item !== 'object') throw new Error('清单中存在无效文件记录。');
      const { path, size, hash } = item as Record<string, unknown>;
      if (typeof path !== 'string' || !path || !validDigest(hash, 'BLAKE2b-512')) {
        throw new Error('清单中存在无效文件记录。');
      }
      if (size !== undefined && (typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0)) {
        throw new Error('清单中存在无效文件大小。');
      }
      const normalizedHash = hash.toLowerCase();
      entries.push({
        path,
        size: size as number | undefined,
        hashes: { 'BLAKE2b-512': normalizedHash },
        expectations: [{ mode: 'all', hashes: { 'BLAKE2b-512': normalizedHash } }],
      });
    }
    if (entries.length === 0) throw new Error('校验清单为空。');
    return { algorithms: collectAlgorithms(entries), createdAt: undefined, files: entries };
  }

  if (record.format === 'CRYPTA-INTEGRITY' && record.version === 2) {
    const files = Array.isArray(record.files) ? record.files : [];
    const entries: ManifestEntry[] = [];
    for (const item of files) {
      if (!item || typeof item !== 'object') throw new Error('清单中存在无效文件记录。');
      const { path, size, hashes } = item as Record<string, unknown>;
      if (typeof path !== 'string' || !path || !hashes || typeof hashes !== 'object' || Array.isArray(hashes)) {
        throw new Error('清单中存在无效文件记录。');
      }
      const normalized: Partial<Record<AlgorithmId, string>> = {};
      for (const [key, value] of Object.entries(hashes)) {
        if (!isAlgorithmId(key) || !validDigest(value, key)) throw new Error('清单中存在无效文件记录。');
        normalized[key] = (value as string).toLowerCase();
      }
      if (Object.keys(normalized).length === 0) throw new Error('清单中存在无效文件记录。');
      if (size !== undefined && (typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0)) {
        throw new Error('清单中存在无效文件大小。');
      }
      entries.push({
        path,
        size: size as number | undefined,
        hashes: normalized,
        expectations: [{ mode: 'all', hashes: normalized }],
      });
    }
    if (entries.length === 0) throw new Error('校验清单为空。');
    const createdAt = typeof record.createdAt === 'string' ? record.createdAt : undefined;
    return { algorithms: collectAlgorithms(entries), createdAt, files: entries };
  }

  return null;
}

function parseTextManifest(text: string): IntegrityManifest {
  const byPath = new Map<string, ManifestEntry>();

  const upsert = (path: string, hash: string, algorithms: AlgorithmId[], mode: 'all' | 'any') => {
    const existing = byPath.get(path);
    const expectationHashes: Partial<Record<AlgorithmId, string>> = {};
    for (const id of algorithms) expectationHashes[id] = hash;

    if (!existing) {
      byPath.set(path, {
        path,
        hashes: { ...expectationHashes },
        expectations: [{ mode, hashes: expectationHashes }],
      });
      return;
    }

    for (const id of algorithms) {
      const previous = existing.hashes[id];
      if (previous !== undefined && previous !== hash) {
        throw new Error(`文件“${path}”存在冲突的 ${id} 校验摘要。`);
      }
      existing.hashes[id] = hash;
    }
    existing.expectations ??= [];
    existing.expectations.push({ mode, hashes: expectationHashes });
  };

  const lines = text.split(/\r?\n/u);
  let labeledAlgorithm: AlgorithmId | undefined;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!.trim();
    if (!line) continue;

    const label = line.match(/^#\s*([^#].*?)\s*$/u);
    if (label) {
      const labelText = label[1]!.trim();
      if (isAlgorithmId(labelText)) labeledAlgorithm = labelText;
      else if (BSD_ALIASES.has(labelText.toUpperCase())) labeledAlgorithm = BSD_ALIASES.get(labelText.toUpperCase());
      else labeledAlgorithm = undefined;
      continue;
    }
    if (line.startsWith('#')) continue;

    const standard = line.match(/^([0-9a-fA-F]{8,128})\s+[ *]?(.+)$/u);
    if (standard && standard[1]!.length % 2 === 0) {
      const digest = standard[1]!;
      const algorithms = labeledAlgorithm ? [labeledAlgorithm] : algorithmsByHexLength(digest.length);
      if (labeledAlgorithm && !validDigest(digest, labeledAlgorithm)) {
        throw new Error(`第 ${index + 1} 行的摘要长度与 ${labeledAlgorithm} 不匹配。`);
      }
      if (algorithms.length === 0) {
        throw new Error(`第 ${index + 1} 行的摘要长度不受支持（不支持 CRC 等非哈希校验和）。`);
      }
      upsert(standard[2]!.trim(), digest.toLowerCase(), algorithms, labeledAlgorithm ? 'all' : 'any');
      continue;
    }

    const bsd = line.match(/^([A-Za-z0-9][A-Za-z0-9 -]*)\((.+)\)\s*=\s*([0-9a-fA-F]+)$/u);
    if (bsd) {
      const id = BSD_ALIASES.get(bsd[1]!.trim().toUpperCase());
      if (id && validDigest(bsd[3], id)) {
        if (labeledAlgorithm && labeledAlgorithm !== id) {
          throw new Error(`第 ${index + 1} 行的算法标签与 BSD 校验记录冲突。`);
        }
        upsert(bsd[2]!, bsd[3]!.toLowerCase(), [id], 'all');
        continue;
      }
    }

    throw new Error(`无法识别第 ${index + 1} 行的校验记录。`);
  }

  const files = [...byPath.values()];
  if (files.length === 0) throw new Error('校验清单为空。');
  return { algorithms: collectAlgorithms(files), files };
}

export function parseManifest(text: string): IntegrityManifest {
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) {
    try {
      const fromJson = parseJsonManifest(JSON.parse(trimmed));
      if (fromJson) return fromJson;
      throw new Error('无法识别该校验清单。');
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('清单')) throw error;
    }
  }
  return parseTextManifest(text);
}

/**
 * Compare calculated hashes with one manifest entry.  Every expectation group
 * is required; within a group, `all` means every algorithm must match while
 * `any` means one candidate algorithm is enough.
 */
export function matchesManifestEntry(
  expected: ManifestEntry,
  actual: Partial<Record<AlgorithmId, string>>,
): boolean {
  const expectations = expected.expectations?.length
    ? expected.expectations
    : [{ mode: 'all' as const, hashes: expected.hashes }];

  return expectations.every(({ mode, hashes }) => {
    const pairs = Object.entries(hashes) as [AlgorithmId, string][];
    if (pairs.length === 0) return false;
    const matches = pairs.map(([id, digest]) => actual[id]?.toLowerCase() === digest.toLowerCase());
    return mode === 'any' ? matches.some(Boolean) : matches.every(Boolean);
  });
}
