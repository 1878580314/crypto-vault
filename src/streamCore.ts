/**
 * CRYPTA V2 STREAM 格式共享核心：主线程引擎（stream.ts）与 OPFS Worker
 * 引擎（stream.worker.ts）此前各自维护了一份逐行重复的格式实现，
 * 任何格式修复都必须改两处。这里只保留一份。
 *
 * Shared CRYPTA V2 STREAM core: the main-thread engine (stream.ts) and the
 * OPFS worker engine (stream.worker.ts) previously each carried a line-by-line
 * duplicate of the format implementation; every format fix had to land twice.
 */
import { decode, encode } from '@msgpack/msgpack';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { createChaChaCipher } from './chacha.ts';
import {
  NONCE_BYTES,
  bytesToArrayBuffer,
  createPassphraseKdf,
  derivePassphraseKey,
  parseKeyDerivationInfo,
  type AlgorithmId,
  type KeyDerivationInfo,
} from './crypto.ts';

export type { AlgorithmId, KeyDerivationInfo };

export interface StreamProgress {
  processed: number;
  total: number;
  ratio: number;
  bytesPerSecond: number;
  phase: 'kdf' | 'data';
  readBytesPerSecond?: number;
  cryptoBytesPerSecond?: number;
  writeBytesPerSecond?: number;
  concurrency?: number;
}

export const STREAM_CHUNK_BYTES = 16 * 1024 * 1024;
/** AEAD 认证标签长度 / AEAD authentication tag length */
export const TAG_BYTES = 16;
const STREAM_MAGIC = new TextEncoder().encode('CRYPTA2S');
const MAX_HEADER_BYTES = 64 * 1024;
/** 解密元数据记录长度上限（密文长度 = 明文 + TAG）/ Encrypted-meta length ceiling */
export const MAX_META_BYTES = 1024 * 1024;
const FILE_SALT_BYTES = 16;
const STREAM_KEY_INFO = new TextEncoder().encode('CRYPTA-V2-STREAM-AEAD-KEY');
const OPFS_TEMP_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const OPFS_TEMP_PREFIX = 'crypta-';
const OPFS_TEMP_SUFFIX = '.tmp';

export interface StreamHeader {
  version: 2;
  algorithm: AlgorithmId;
  chunkSize: number;
  fileSalt: Uint8Array;
  keyDerivation: KeyDerivationInfo;
}

export interface StreamMeta {
  kind: 'file';
  name: string;
  mime: string;
  size: number;
  createdAt: string;
  chunks: number;
}

export interface StreamCipher {
  encrypt(plaintext: Uint8Array, nonce: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array, nonce: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
}

export class StreamUserCancelledError extends Error {
  constructor() {
    super('操作已由用户停止。');
    this.name = 'StreamUserCancelledError';
  }
}

export function u32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new Error('CRYPTA 记录长度超出范围。');
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}

export function readU32(input: Uint8Array, offset = 0): number {
  if (input.byteLength < offset + 4) throw new Error('CRYPTA 流式容器已截断。');
  return new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(offset, false);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let diff = 0;
  for (let index = 0; index < left.byteLength; index += 1) diff |= left[index] ^ right[index];
  return diff === 0;
}

export function recordNonce(index: number): Uint8Array {
  if (!Number.isInteger(index) || index < 0 || index > 0xffff_ffff) throw new Error('CRYPTA 分块索引超出范围。');
  const nonce = new Uint8Array(NONCE_BYTES);
  new DataView(nonce.buffer).setUint32(8, index, false);
  return nonce;
}

export function recordAad(prefix: Uint8Array, type: 0 | 1, index: number, plaintextLength: number): Uint8Array {
  return concat(prefix, Uint8Array.of(type), u32(index), u32(plaintextLength));
}

export function parseStreamHeader(value: unknown): StreamHeader {
  if (!value || typeof value !== 'object') throw new Error('CRYPTA 流式头部无效。');
  const header = value as Record<string, unknown>;
  if (header.version !== 2) throw new Error('不支持该 CRYPTA 流式版本。');
  if (header.algorithm !== 'AES-256-GCM' && header.algorithm !== 'CHACHA20-POLY1305') {
    throw new Error('密文使用了不受支持的算法。');
  }
  if (
    typeof header.chunkSize !== 'number' ||
    !Number.isInteger(header.chunkSize) ||
    header.chunkSize < 1024 * 1024 ||
    header.chunkSize > 64 * 1024 * 1024
  ) {
    throw new Error('CRYPTA 分块大小无效。');
  }
  if (!(header.fileSalt instanceof Uint8Array) || header.fileSalt.byteLength !== FILE_SALT_BYTES) {
    throw new Error('CRYPTA 文件子密钥盐值无效。');
  }
  return {
    version: 2,
    algorithm: header.algorithm,
    chunkSize: header.chunkSize,
    fileSalt: header.fileSalt,
    keyDerivation: parseKeyDerivationInfo(header.keyDerivation),
  };
}

export function deriveFileKey(masterKey: Uint8Array, fileSalt: Uint8Array): Uint8Array {
  if (masterKey.byteLength !== 32) throw new Error('无效的 256 位主密钥。');
  if (fileSalt.byteLength !== FILE_SALT_BYTES) throw new Error('无效的文件子密钥盐值。');
  return hkdf(sha256, masterKey, fileSalt, STREAM_KEY_INFO, 32);
}

export function parseStreamMeta(value: unknown): StreamMeta {
  if (!value || typeof value !== 'object') throw new Error('解密后的文件元数据无效。');
  const meta = value as Record<string, unknown>;
  if (meta.kind !== 'file') throw new Error('该流式密文不包含文件。');
  if (typeof meta.name !== 'string' || typeof meta.mime !== 'string' || typeof meta.createdAt !== 'string') {
    throw new Error('解密后的文件元数据无效。');
  }
  if (typeof meta.size !== 'number' || !Number.isSafeInteger(meta.size) || meta.size < 0) {
    throw new Error('解密后的文件长度无效。');
  }
  if (typeof meta.chunks !== 'number' || !Number.isInteger(meta.chunks) || meta.chunks < 0 || meta.chunks > 0xffff_fffe) {
    throw new Error('解密后的分块计数无效。');
  }
  return meta as unknown as StreamMeta;
}

export async function createCipher(algorithm: AlgorithmId, key: Uint8Array): Promise<StreamCipher> {
  if (key.byteLength !== 32) throw new Error('无效的 256 位密钥。');
  if (algorithm === 'AES-256-GCM') {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      bytesToArrayBuffer(key),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    return {
      encrypt: async (plaintext: Uint8Array, nonce: Uint8Array, aad: Uint8Array) => new Uint8Array(
        await crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: bytesToArrayBuffer(nonce),
            additionalData: bytesToArrayBuffer(aad),
            tagLength: 128,
          },
          cryptoKey,
          bytesToArrayBuffer(plaintext),
        ),
      ),
      decrypt: async (ciphertext: Uint8Array, nonce: Uint8Array, aad: Uint8Array) => new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: bytesToArrayBuffer(nonce),
            additionalData: bytesToArrayBuffer(aad),
            tagLength: 128,
          },
          cryptoKey,
          bytesToArrayBuffer(ciphertext),
        ),
      ),
    };
  }
  const chacha = await createChaChaCipher(key);
  return {
    encrypt: async (plaintext: Uint8Array, nonce: Uint8Array, aad: Uint8Array) => chacha.encrypt(plaintext, nonce, aad),
    decrypt: async (ciphertext: Uint8Array, nonce: Uint8Array, aad: Uint8Array) => chacha.decrypt(ciphertext, nonce, aad),
  };
}

/** 统一的流式容器前缀解析：此前 Worker 版缺少对 MessagePack 解析失败的兜底。
 *  Unified container-prefix parsing; the worker copy previously lacked a
 *  guard around MessagePack decoding. */
export async function readStreamPrefix(file: File): Promise<{
  header: StreamHeader;
  prefix: Uint8Array;
  offset: number;
}> {
  if (file.size < STREAM_MAGIC.byteLength + 4) throw new Error('文件不是有效的 CRYPTA 流式密文。');
  const fixed = new Uint8Array(await file.slice(0, STREAM_MAGIC.byteLength + 4).arrayBuffer());
  if (!equalBytes(fixed.subarray(0, STREAM_MAGIC.byteLength), STREAM_MAGIC)) {
    throw new Error('文件不是 CRYPTA V2 流式密文。');
  }
  const headerLength = readU32(fixed, STREAM_MAGIC.byteLength);
  if (headerLength === 0 || headerLength > MAX_HEADER_BYTES) throw new Error('CRYPTA 流式头部长度无效。');
  const prefixLength = STREAM_MAGIC.byteLength + 4 + headerLength;
  if (prefixLength > file.size) throw new Error('CRYPTA 流式头部已截断。');
  const prefix = new Uint8Array(await file.slice(0, prefixLength).arrayBuffer());
  let decoded: unknown;
  try {
    decoded = decode(prefix.subarray(STREAM_MAGIC.byteLength + 4));
  } catch {
    throw new Error('无法解析 CRYPTA 流式头部。');
  }
  return { header: parseStreamHeader(decoded), prefix, offset: prefixLength };
}

export function encodeStreamHeader(header: StreamHeader): { headerBytes: Uint8Array; prefix: Uint8Array } {
  const headerBytes = encode(header);
  return { headerBytes, prefix: concat(STREAM_MAGIC, u32(headerBytes.byteLength), headerBytes) };
}

export function encodeStreamMetaBytes(meta: StreamMeta): Uint8Array {
  return encode(meta);
}

export function decodeStreamMetaBytes(metaBytes: Uint8Array): unknown {
  try {
    return decode(metaBytes);
  } catch {
    throw new Error('解密后的文件元数据损坏。');
  }
}

export function createFileSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(FILE_SALT_BYTES));
}

export interface PipelineMetrics {
  readBytes: number;
  readMs: number;
  cryptoBytes: number;
  cryptoMs: number;
  writeBytes: number;
  writeMs: number;
  concurrency: number;
}

export function zeroMetrics(concurrency: number): PipelineMetrics {
  return { readBytes: 0, readMs: 0, cryptoBytes: 0, cryptoMs: 0, writeBytes: 0, writeMs: 0, concurrency };
}

function stageRate(bytes: number, milliseconds: number): number {
  return milliseconds > 0 ? bytes / (milliseconds / 1000) : 0;
}

export function createProgressReporter(
  total: number,
  metrics: PipelineMetrics,
  onProgress?: (progress: StreamProgress) => void,
) {
  const started = performance.now();
  return (processed: number) => {
    if (!onProgress) return;
    const seconds = Math.max((performance.now() - started) / 1000, 0.001);
    onProgress({
      processed,
      total,
      ratio: total === 0 ? 1 : Math.min(processed / total, 1),
      bytesPerSecond: processed / seconds,
      phase: 'data',
      readBytesPerSecond: stageRate(metrics.readBytes, metrics.readMs),
      cryptoBytesPerSecond: stageRate(metrics.cryptoBytes, metrics.cryptoMs),
      writeBytesPerSecond: stageRate(metrics.writeBytes, metrics.writeMs),
      concurrency: metrics.concurrency,
    });
  };
}

export interface KeyInputs {
  rawKey?: Uint8Array;
  passphrase?: string;
  keyDerivation?: KeyDerivationInfo;
}

/** 统一加解密密钥解析：此前 Worker 版会静默丢弃调用方传入的 keyDerivation，
 *  强制使用新盐；现在两条路径行为一致。
 *  Unified key resolution; the worker copy previously silently dropped a
 *  caller-supplied keyDerivation and always minted a fresh salt. */
export async function resolveEncryptionKey(
  inputs: KeyInputs,
  onProgress?: (progress: StreamProgress) => void,
): Promise<{ key: Uint8Array; kdf: KeyDerivationInfo }> {
  if (inputs.keyDerivation?.type === 'argon2id' || inputs.passphrase !== undefined) {
    const kdf = inputs.keyDerivation?.type === 'argon2id' ? inputs.keyDerivation : createPassphraseKdf();
    const passphrase = inputs.passphrase ?? '';
    const key = await derivePassphraseKey(passphrase, kdf, (ratio) => {
      onProgress?.({ processed: 0, total: 0, ratio, bytesPerSecond: 0, phase: 'kdf' });
    });
    return { key, kdf };
  }
  if (!inputs.rawKey) throw new Error('缺少 256 位密钥。');
  return { key: inputs.rawKey.slice(), kdf: { type: 'raw' } };
}

export async function resolveDecryptionKey(
  keyDerivation: KeyDerivationInfo,
  inputs: KeyInputs,
  onProgress?: (progress: StreamProgress) => void,
): Promise<Uint8Array> {
  if (keyDerivation.type === 'argon2id') {
    if (inputs.passphrase === undefined) throw new Error('该密文需要文本口令。');
    return derivePassphraseKey(inputs.passphrase, keyDerivation, (ratio) => {
      onProgress?.({ processed: 0, total: 0, ratio, bytesPerSecond: 0, phase: 'kdf' });
    });
  }
  if (!inputs.rawKey) throw new Error('该密文需要 256 位原始密钥。');
  return inputs.rawKey.slice();
}

/** OPFS 临时文件命名 / OPFS temp-file naming */
export function createOpfsTempName(): string {
  const taskId = crypto.randomUUID?.() ?? Array.from(
    crypto.getRandomValues(new Uint8Array(8)),
    (value) => value.toString(16).padStart(2, '0'),
  ).join('');
  return `${OPFS_TEMP_PREFIX}${Date.now().toString(36)}-${taskId}${OPFS_TEMP_SUFFIX}`;
}

async function cleanupExpiredOpfsTemps(root: FileSystemDirectoryHandle): Promise<void> {
  const cutoff = Date.now() - OPFS_TEMP_MAX_AGE_MS;
  try {
    const entries = root.entries?.();
    if (!entries) return;
    for await (const [name, entry] of entries) {
      if (!name.startsWith(OPFS_TEMP_PREFIX) || !name.endsWith(OPFS_TEMP_SUFFIX) || entry.kind !== 'file') continue;
      try {
        const file = await (entry as FileSystemFileHandle).getFile();
        // 缺失/无效的时间戳不足以证明文件可回收 / A missing/invalid timestamp is not enough evidence to reclaim a file.
        if (!Number.isFinite(file.lastModified) || file.lastModified <= 0 || file.lastModified > cutoff) continue;
        await root.removeEntry(name).catch(() => undefined);
      } catch {
        // 活跃/锁定的文件或无 getFile() 的实现保持原样 / Active/locked files or implementations without getFile() stay untouched.
      }
    }
  } catch {
    // 部分实现不支持目录遍历 / Directory iteration is optional on some implementations.
  }
}

export async function ensureOpfsCapacity(requiredBytes: number): Promise<void> {
  const estimate = await navigator.storage?.estimate?.();
  if (!estimate?.quota) return;
  const usage = estimate.usage ?? 0;
  const available = Math.max(0, estimate.quota - usage);
  // 给元数据、浏览器内部开销和下载导出过程留出余量。 / Headroom for metadata, browser internals and the download/export path.
  const requiredWithHeadroom = Math.ceil(requiredBytes * 1.08 + 16 * 1024 * 1024);
  if (available < requiredWithHeadroom) {
    throw new Error(`浏览器临时存储空间不足：至少还需要约 ${Math.ceil(requiredWithHeadroom / 1024 / 1024)} MiB 可用空间。`);
  }
}

export async function prepareOpfsTempDirectory(expectedBytes: number): Promise<FileSystemDirectoryHandle> {
  if (typeof navigator.storage?.getDirectory !== 'function') {
    throw new Error('当前浏览器既不支持系统文件保存，也不支持大文件临时存储。');
  }
  const root = await navigator.storage.getDirectory();
  // 只回收至少一天未修改的文件，不碰其他标签页的活跃临时文件 / Reclaim only files untouched for a day; never touch active temps.
  await cleanupExpiredOpfsTemps(root);
  await ensureOpfsCapacity(expectedBytes);
  return root;
}

/**
 * 有界并发有序流水线：读/加解密在前台并发准备（最多 concurrency 个在途），
 * 写盘严格按序号顺序提交。主线程与 Worker 的加解密循环是同一算法的四份拷贝，
 * 这里只保留一份。
 * Bounded-concurrency ordered pipeline: read/crypto stages run ahead (at most
 * `concurrency` in flight) while writes commit strictly in order. The four
 * encrypt/decrypt loops were copies of this same algorithm; only one remains.
 */
export async function runBoundedPipeline<Prepared>(
  total: number,
  concurrency: number,
  prepare: (index: number) => Promise<Prepared>,
  consume: (index: number, prepared: Prepared) => Promise<void>,
  shouldCancel?: () => boolean,
): Promise<void> {
  const inFlight = new Map<number, Promise<Prepared>>();
  const schedule = (index: number) => {
    if (index < total) inFlight.set(index, prepare(index));
  };
  for (let index = 0; index < Math.min(concurrency, total); index += 1) schedule(index);
  for (let index = 0; index < total; index += 1) {
    if (shouldCancel?.()) throw new StreamUserCancelledError();
    const prepared = await inFlight.get(index)!;
    inFlight.delete(index);
    schedule(index + concurrency);
    await consume(index, prepared);
  }
}
