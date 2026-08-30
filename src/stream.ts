import { decode, encode } from '@msgpack/msgpack';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { createChaChaCipher } from './chacha';
import {
  NONCE_BYTES,
  createPassphraseKdf,
  derivePassphraseKey,
  parseKeyDerivationInfo,
  type AlgorithmId,
  type KeyDerivationInfo,
  type PayloadMeta,
} from './crypto';

export const STREAM_CHUNK_BYTES = 16 * 1024 * 1024;
export const STREAM_THRESHOLD_BYTES = 64 * 1024 * 1024;
const TAG_BYTES = 16;
const STREAM_MAGIC = new TextEncoder().encode('CRYPTA2S');
const MAX_HEADER_BYTES = 64 * 1024;
const MAX_META_BYTES = 1024 * 1024;
const FILE_SALT_BYTES = 16;
const STREAM_KEY_INFO = new TextEncoder().encode('CRYPTA-V2-STREAM-AEAD-KEY');
const OPFS_TEMP_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const OPFS_TEMP_PREFIX = 'crypta-';
const OPFS_TEMP_SUFFIX = '.tmp';

interface StreamHeader {
  version: 2;
  algorithm: AlgorithmId;
  chunkSize: number;
  fileSalt: Uint8Array;
  keyDerivation: KeyDerivationInfo;
}

interface StreamMeta {
  kind: 'file';
  name: string;
  mime: string;
  size: number;
  createdAt: string;
  chunks: number;
}

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

export interface StreamEncryptOptions {
  algorithm: AlgorithmId;
  keyDerivation?: KeyDerivationInfo;
  rawKey?: Uint8Array;
  passphrase?: string;
  onProgress?: (progress: StreamProgress) => void;
  shouldCancel?: () => boolean;
}

export interface StreamFileResult extends PayloadMeta {
  savedAs: string;
  exportFile?: File;
  storage: 'direct' | 'opfs';
  cleanup?: () => Promise<void>;
}

export interface StreamDecryptOptions {
  rawKey?: Uint8Array;
  passphrase?: string;
  onProgress?: (progress: StreamProgress) => void;
  shouldCancel?: () => boolean;
}

export class StreamUserCancelledError extends Error {
  constructor() {
    super('操作已由用户停止。');
    this.name = 'StreamUserCancelledError';
  }
}

export class SavePickerCancelledError extends Error {
  constructor() {
    super('未选择保存位置，未开始处理文件。');
    this.name = 'SavePickerCancelledError';
  }
}

interface SaveHandle {
  name: string;
  createWritable(): Promise<{
    write(data: Uint8Array): Promise<void>;
    close(): Promise<void>;
    abort(reason?: unknown): Promise<void>;
  }>;
}

interface StreamDestination {
  name: string;
  storage: 'direct' | 'opfs';
  writable: {
    write(data: Uint8Array): Promise<void>;
    close(): Promise<void>;
    abort(reason?: unknown): Promise<void>;
  };
  finalize(): Promise<File | undefined>;
  cleanup(): Promise<void>;
}

type SavePicker = (options?: {
  suggestedName?: string;
  types?: Array<{ description?: string; accept: Record<string, string[]> }>;
}) => Promise<SaveHandle>;

function savePicker(): SavePicker | undefined {
  return (window as unknown as { showSaveFilePicker?: SavePicker }).showSaveFilePicker?.bind(window);
}

export function supportsStreamingFileSave(): boolean {
  return typeof savePicker() === 'function' || typeof navigator.storage?.getDirectory === 'function';
}

export function usesSystemFilePickerForStreaming(): boolean {
  return !isLikelyMobile() && typeof savePicker() === 'function';
}

function supportsOptimizedOpfsWorker(): boolean {
  return (
    typeof Worker === 'function' &&
    !usesSystemFilePickerForStreaming() &&
    typeof navigator.storage?.getDirectory === 'function'
  );
}

function isLikelyMobile(): boolean {
  if (typeof navigator === 'undefined') return false;
  const userAgentData = (navigator as Navigator & { userAgentData?: { mobile?: boolean } }).userAgentData;
  if (typeof userAgentData?.mobile === 'boolean') return userAgentData.mobile;
  return /Android|iPhone|iPad|iPod|Mobile/iu.test(navigator.userAgent);
}

function streamConcurrency(algorithm: AlgorithmId): number {
  if (algorithm !== 'AES-256-GCM') return 1;
  const cores = typeof navigator === 'undefined' ? 4 : Math.max(1, navigator.hardwareConcurrency || 4);
  if (isLikelyMobile()) return cores >= 4 ? 2 : 1;
  if (cores >= 8) return 3;
  return cores >= 4 ? 2 : 1;
}

function createOpfsTempName(): string {
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

async function ensureOpfsCapacity(requiredBytes: number): Promise<void> {
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

async function openOpfsDestination(suggestedName: string, expectedBytes: number): Promise<StreamDestination> {
  if (typeof navigator.storage?.getDirectory !== 'function') {
    throw new Error('当前浏览器既不支持系统文件保存，也不支持大文件临时存储。');
  }
  const root = await navigator.storage.getDirectory();
  // 只回收至少一天未修改的文件，不碰其他标签页的活跃临时文件 / Reclaim only files untouched for a day; never touch active temps.
  await cleanupExpiredOpfsTemps(root);
  await ensureOpfsCapacity(expectedBytes);
  const tempName = createOpfsTempName();
  let handle: FileSystemFileHandle;
  let writable: Awaited<ReturnType<FileSystemFileHandle['createWritable']>>;
  try {
    handle = await root.getFileHandle(tempName, { create: true });
    writable = await handle.createWritable();
  } catch (error) {
    // 打开 writer 失败时文件可能已存在 / The file may already exist even when opening its writer fails.
    await root.removeEntry(tempName).catch(() => undefined);
    throw error;
  }
  let closed = false;
  const cleanup = async () => {
    await root.removeEntry(tempName).catch(() => undefined);
  };
  return {
    name: suggestedName,
    storage: 'opfs',
    writable: {
      write: (data) => writable.write(bytesToArrayBuffer(data)),
      close: async () => {
        await writable.close();
        closed = true;
      },
      abort: async (reason) => {
        if (!closed) await writable.abort(reason).catch(() => undefined);
        await cleanup();
      },
    },
    finalize: async () => {
      const file = await handle.getFile();
      // File 对象仍由 OPFS 后端支持，不会把整个多 GB 文件一次性复制到 JS 堆中。
      // The File stays backed by OPFS; multi-GB content is never copied into the JS heap at once.
      return new File([file], suggestedName, { type: file.type || 'application/octet-stream', lastModified: Date.now() });
    },
    cleanup,
  };
}

function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  if (
    bytes.buffer instanceof ArrayBuffer &&
    bytes.byteOffset === 0 &&
    bytes.byteLength === bytes.buffer.byteLength
  ) {
    return bytes.buffer;
  }
  return bytes.slice().buffer;
}

function u32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new Error('CRYPTA 记录长度超出范围。');
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}

function readU32(input: Uint8Array, offset = 0): number {
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

function recordNonce(index: number): Uint8Array {
  if (!Number.isInteger(index) || index < 0 || index > 0xffff_ffff) throw new Error('CRYPTA 分块索引超出范围。');
  const nonce = new Uint8Array(NONCE_BYTES);
  new DataView(nonce.buffer).setUint32(8, index, false);
  return nonce;
}

function recordAad(prefix: Uint8Array, type: 0 | 1, index: number, plaintextLength: number): Uint8Array {
  return concat(prefix, Uint8Array.of(type), u32(index), u32(plaintextLength));
}

function parseStreamHeader(value: unknown): StreamHeader {
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

function deriveFileKey(masterKey: Uint8Array, fileSalt: Uint8Array): Uint8Array {
  if (masterKey.byteLength !== 32) throw new Error('无效的 256 位主密钥。');
  if (fileSalt.byteLength !== FILE_SALT_BYTES) throw new Error('无效的文件子密钥盐值。');
  return hkdf(sha256, masterKey, fileSalt, STREAM_KEY_INFO, 32);
}

function parseStreamMeta(value: unknown): StreamMeta {
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

async function createCipher(algorithm: AlgorithmId, key: Uint8Array) {
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

function assertNotCancelled(shouldCancel?: () => boolean) {
  if (shouldCancel?.()) throw new StreamUserCancelledError();
}

function describeFileSystemError(error: unknown, action: 'read' | 'open' | 'write' | 'close'): Error {
  if (!(error instanceof DOMException)) {
    return error instanceof Error ? error : new Error('文件系统操作失败。');
  }

  if (error.name === 'QuotaExceededError') {
    return new Error('保存失败：目标磁盘可用空间不足。请更换磁盘或释放足够空间后重试。');
  }
  if (error.name === 'NotAllowedError' || error.name === 'NoModificationAllowedError') {
    return new Error('保存失败：浏览器没有该位置的写入权限。请更换保存目录后重试。');
  }
  if (error.name === 'NotReadableError') {
    return new Error(action === 'read'
      ? '读取源文件失败。请确认文件仍存在、未被其他程序独占，并尝试复制到本地磁盘后重试。'
      : '目标文件无法访问。请更换保存位置后重试。');
  }
  if (error.name === 'AbortError') {
    if (action === 'read') {
      return new Error('源文件读取被系统或浏览器中止。若文件位于移动硬盘、网络盘或同步目录，请先复制到本地磁盘后重试。');
    }
    return new Error('文件写入被系统或浏览器中止。请确认目标磁盘空间充足、连接稳定，并尝试更换本地保存目录。');
  }
  return new Error(`文件系统操作失败：${error.message || error.name}`);
}

interface PipelineMetrics {
  readBytes: number;
  readMs: number;
  cryptoBytes: number;
  cryptoMs: number;
  writeBytes: number;
  writeMs: number;
  concurrency: number;
}

function stageRate(bytes: number, milliseconds: number): number {
  return milliseconds > 0 ? bytes / (milliseconds / 1000) : 0;
}

function progressReporter(
  total: number,
  metrics: PipelineMetrics,
  callback?: (progress: StreamProgress) => void,
) {
  const started = performance.now();
  return (processed: number) => {
    if (!callback) return;
    const seconds = Math.max((performance.now() - started) / 1000, 0.001);
    callback({
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

async function resolveEncryptionKey(options: StreamEncryptOptions): Promise<{ key: Uint8Array; kdf: KeyDerivationInfo }> {
  if (options.keyDerivation?.type === 'argon2id' || options.passphrase !== undefined) {
    const kdf = options.keyDerivation?.type === 'argon2id' ? options.keyDerivation : createPassphraseKdf();
    const passphrase = options.passphrase ?? '';
    const key = await derivePassphraseKey(passphrase, kdf, (ratio) => {
      options.onProgress?.({ processed: 0, total: 0, ratio, bytesPerSecond: 0, phase: 'kdf' });
    });
    return { key, kdf };
  }
  if (!options.rawKey) throw new Error('缺少 256 位密钥。');
  return { key: options.rawKey.slice(), kdf: { type: 'raw' } };
}

async function resolveDecryptionKey(
  keyDerivation: KeyDerivationInfo,
  options: StreamDecryptOptions,
): Promise<Uint8Array> {
  if (keyDerivation.type === 'argon2id') {
    if (options.passphrase === undefined) throw new Error('该密文需要文本口令。');
    return derivePassphraseKey(options.passphrase, keyDerivation, (ratio) => {
      options.onProgress?.({ processed: 0, total: 0, ratio, bytesPerSecond: 0, phase: 'kdf' });
    });
  }
  if (!options.rawKey) throw new Error('该密文需要 256 位原始密钥。');
  return options.rawKey.slice();
}

async function openDestination(suggestedName: string, encrypted: boolean, expectedBytes: number): Promise<StreamDestination> {
  const picker = savePicker();
  if (!isLikelyMobile() && picker) {
    try {
      const handle = encrypted
        ? await picker({
            suggestedName,
            types: [{ description: 'CRYPTA encrypted file', accept: { 'application/x-crypta': ['.crypta'] } }],
          })
        : await picker({ suggestedName });
      const writable = await handle.createWritable();
      return {
        name: handle.name,
        storage: 'direct',
        writable,
        finalize: async () => undefined,
        cleanup: async () => undefined,
      };
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw new SavePickerCancelledError();
      throw describeFileSystemError(error, 'open');
    }
  }
  return openOpfsDestination(suggestedName, expectedBytes);
}

interface OpfsWorkerResult extends PayloadMeta {
  savedAs: string;
  tempName: string;
  exportFile: File;
  storage: 'opfs';
}

async function cleanupOpfsTemp(tempName: string): Promise<void> {
  if (typeof navigator.storage?.getDirectory !== 'function') return;
  const root = await navigator.storage.getDirectory();
  await root.removeEntry(tempName).catch(() => undefined);
}

function runOptimizedOpfsWorker(
  request: {
    operation: 'encrypt' | 'decrypt';
    file: File;
    algorithm?: AlgorithmId;
    rawKey?: Uint8Array;
    passphrase?: string;
    suggestedName: string;
    expectedBytes: number;
  },
  options: StreamEncryptOptions | StreamDecryptOptions,
): Promise<StreamFileResult> {
  const runAttempt = (attempt: number): Promise<StreamFileResult> => new Promise((resolve, reject) => {
    let worker: Worker;
    try {
      worker = new Worker(new URL('./stream.worker.ts', import.meta.url), {
        type: 'module',
        name: 'crypta-stream-engine',
      });
    } catch (error) {
      if (attempt === 0) {
        void runAttempt(1).then(resolve, reject);
        return;
      }
      reject(error instanceof Error ? error : new Error('高性能流式 Worker 无法启动。'));
      return;
    }

    let ready = false;
    let started = false;
    let settled = false;
    let cancelSent = false;
    const cancelTimer = window.setInterval(() => {
      if (!cancelSent && started && options.shouldCancel?.()) {
        cancelSent = true;
        worker.postMessage({ type: 'cancel' });
      }
    }, 60);

    const dispose = () => {
      window.clearInterval(cancelTimer);
      worker.terminate();
    };

    const retryColdStart = (error: Error) => {
      if (settled) return;
      settled = true;
      dispose();
      if (attempt === 0 && !started) {
        void runAttempt(1).then(resolve, reject);
      } else {
        reject(error);
      }
    };

    worker.onerror = (event) => {
      const error = new Error(event.message || '高性能流式 Worker 运行失败。');
      if (!ready || !started) retryColdStart(error);
      else {
        if (settled) return;
        settled = true;
        dispose();
        reject(error);
      }
    };

    worker.onmessage = (event: MessageEvent<{
      type: 'ready' | 'progress' | 'done' | 'error';
      progress?: StreamProgress;
      result?: OpfsWorkerResult;
      error?: { name: string; message: string };
    }>) => {
      if (event.data.type === 'ready') {
        if (settled) return;
        ready = true;
        started = true;
        worker.postMessage({ type: 'start', ...request });
        return;
      }
      if (event.data.type === 'progress' && event.data.progress) {
        options.onProgress?.(event.data.progress);
        return;
      }
      if (event.data.type === 'error') {
        if (settled) return;
        const error = event.data.error;
        settled = true;
        dispose();
        if (error?.name === 'StreamUserCancelledError') reject(new StreamUserCancelledError());
        else reject(new Error(error?.message || '高性能流式处理失败。'));
        return;
      }
      if (event.data.type === 'done' && event.data.result) {
        if (settled) return;
        const result = event.data.result;
        settled = true;
        dispose();
        resolve({
          ...result,
          cleanup: () => cleanupOpfsTemp(result.tempName),
        });
      }
    };
  });

  return runAttempt(0);
}

export async function encryptFileStreaming(file: File, options: StreamEncryptOptions): Promise<StreamFileResult> {
  const expectedBytes = file.size + Math.ceil(file.size / STREAM_CHUNK_BYTES) * (TAG_BYTES + 4) + 1024 * 1024;
  if (supportsOptimizedOpfsWorker()) {
    return runOptimizedOpfsWorker({
      operation: 'encrypt',
      file,
      algorithm: options.algorithm,
      rawKey: options.rawKey,
      passphrase: options.passphrase,
      suggestedName: `${file.name}.crypta`,
      expectedBytes,
    }, options);
  }
  const destination = await openDestination(`${file.name}.crypta`, true, expectedBytes);
  const { writable } = destination;
  let masterKey: Uint8Array | undefined;
  let fileKey: Uint8Array | undefined;
  try {
    assertNotCancelled(options.shouldCancel);
    const resolved = await resolveEncryptionKey(options);
    masterKey = resolved.key;
    const { kdf } = resolved;
    assertNotCancelled(options.shouldCancel);

    const fileSalt = crypto.getRandomValues(new Uint8Array(FILE_SALT_BYTES));
    fileKey = deriveFileKey(masterKey, fileSalt);
    const chunks = Math.ceil(file.size / STREAM_CHUNK_BYTES);
    if (chunks > 0xffff_fffe) throw new Error('文件过大，超出当前 CRYPTA 流式格式容量。');
    const header: StreamHeader = {
      version: 2,
      algorithm: options.algorithm,
      chunkSize: STREAM_CHUNK_BYTES,
      fileSalt,
      keyDerivation: kdf,
    };
    const headerBytes = encode(header);
    const prefix = concat(STREAM_MAGIC, u32(headerBytes.byteLength), headerBytes);
    const meta: StreamMeta = {
      kind: 'file',
      name: file.name,
      mime: file.type || 'application/octet-stream',
      size: file.size,
      createdAt: new Date().toISOString(),
      chunks,
    };
    const metaBytes = encode(meta);
    const cipher = await createCipher(options.algorithm, fileKey);
    const encryptedMeta = await cipher.encrypt(metaBytes, recordNonce(0), recordAad(prefix, 0, 0, metaBytes.byteLength));

    try {
      await writable.write(prefix);
      await writable.write(u32(encryptedMeta.byteLength));
      await writable.write(encryptedMeta);
    } catch (error) {
      throw describeFileSystemError(error, 'write');
    }

    const concurrency = streamConcurrency(options.algorithm);
    const metrics: PipelineMetrics = {
      readBytes: 0,
      readMs: 0,
      cryptoBytes: 0,
      cryptoMs: 0,
      writeBytes: 0,
      writeMs: 0,
      concurrency,
    };
    const report = progressReporter(file.size, metrics, options.onProgress);
    let processed = 0;
    type PreparedEncryptedChunk = {
      encrypted: Uint8Array;
      plaintextLength: number;
    };
    const prepareChunk = async (chunk: number): Promise<PreparedEncryptedChunk> => {
      const start = chunk * STREAM_CHUNK_BYTES;
      const end = Math.min(start + STREAM_CHUNK_BYTES, file.size);
      let plaintext: Uint8Array;
      const readStarted = performance.now();
      try {
        plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());
      } catch (error) {
        throw describeFileSystemError(error, 'read');
      }
      metrics.readBytes += plaintext.byteLength;
      metrics.readMs += performance.now() - readStarted;
      const index = chunk + 1;
      const cryptoStarted = performance.now();
      const encrypted = await cipher.encrypt(
        plaintext,
        recordNonce(index),
        recordAad(prefix, 1, index, plaintext.byteLength),
      );
      metrics.cryptoBytes += plaintext.byteLength;
      metrics.cryptoMs += performance.now() - cryptoStarted;
      return { encrypted, plaintextLength: plaintext.byteLength };
    };

    const inFlight = new Map<number, Promise<PreparedEncryptedChunk>>();
    const schedule = (chunk: number) => {
      if (chunk < chunks) inFlight.set(chunk, prepareChunk(chunk));
    };
    for (let chunk = 0; chunk < Math.min(concurrency, chunks); chunk += 1) schedule(chunk);

    for (let chunk = 0; chunk < chunks; chunk += 1) {
      assertNotCancelled(options.shouldCancel);
      const prepared = await inFlight.get(chunk)!;
      inFlight.delete(chunk);
      schedule(chunk + concurrency);
      const writeStarted = performance.now();
      try {
        await writable.write(u32(prepared.encrypted.byteLength));
        await writable.write(prepared.encrypted);
      } catch (error) {
        throw describeFileSystemError(error, 'write');
      }
      metrics.writeBytes += prepared.encrypted.byteLength + 4;
      metrics.writeMs += performance.now() - writeStarted;
      processed += prepared.plaintextLength;
      report(processed);
    }
    try {
      await writable.close();
    } catch (error) {
      throw describeFileSystemError(error, 'close');
    }
    const exportFile = await destination.finalize();
    return {
      ...meta,
      algorithm: options.algorithm,
      savedAs: destination.name,
      exportFile,
      storage: destination.storage,
      cleanup: destination.storage === 'opfs' ? destination.cleanup : undefined,
    };
  } catch (error) {
    await writable.abort(error).catch(() => undefined);
    throw error;
  } finally {
    fileKey?.fill(0);
    masterKey?.fill(0);
  }
}

async function readStreamPrefix(file: File): Promise<{
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

export async function inspectStreamingFile(file: File): Promise<StreamHeader> {
  return (await readStreamPrefix(file)).header;
}

export async function decryptFileStreaming(file: File, options: StreamDecryptOptions): Promise<StreamFileResult> {
  const suggestedName = file.name.replace(/\.crypta$/iu, '') || 'decrypted.bin';
  if (supportsOptimizedOpfsWorker()) {
    return runOptimizedOpfsWorker({
      operation: 'decrypt',
      file,
      rawKey: options.rawKey,
      passphrase: options.passphrase,
      suggestedName,
      expectedBytes: file.size,
    }, options);
  }
  const destination = await openDestination(suggestedName, false, file.size);
  const { writable } = destination;
  let masterKey: Uint8Array | undefined;
  let fileKey: Uint8Array | undefined;
  try {
    const { header, prefix, offset: prefixOffset } = await readStreamPrefix(file);
    assertNotCancelled(options.shouldCancel);
    masterKey = await resolveDecryptionKey(header.keyDerivation, options);
    fileKey = deriveFileKey(masterKey, header.fileSalt);
    const cipher = await createCipher(header.algorithm, fileKey);

    if (prefixOffset + 4 > file.size) throw new Error('CRYPTA 文件缺少受保护元数据。');
    const metaLengthBytes = new Uint8Array(await file.slice(prefixOffset, prefixOffset + 4).arrayBuffer());
    const encryptedMetaLength = readU32(metaLengthBytes);
    if (encryptedMetaLength <= TAG_BYTES || encryptedMetaLength > MAX_META_BYTES) throw new Error('CRYPTA 元数据记录长度无效。');
    const metaEnd = prefixOffset + 4 + encryptedMetaLength;
    if (metaEnd > file.size) throw new Error('CRYPTA 元数据记录已截断。');
    const encryptedMeta = new Uint8Array(await file.slice(prefixOffset + 4, metaEnd).arrayBuffer());
    const metaPlainLength = encryptedMetaLength - TAG_BYTES;
    let metaBytes: Uint8Array;
    try {
      metaBytes = await cipher.decrypt(
        encryptedMeta,
        recordNonce(0),
        recordAad(prefix, 0, 0, metaPlainLength),
      );
    } catch {
      throw new Error('解密失败：密钥/口令错误，或密文头部已被修改。');
    }
    let metaDecoded: unknown;
    try {
      metaDecoded = decode(metaBytes);
    } catch {
      throw new Error('解密后的文件元数据损坏。');
    }
    const meta = parseStreamMeta(metaDecoded);
    const expectedChunks = Math.ceil(meta.size / header.chunkSize);
    if (expectedChunks !== meta.chunks) throw new Error('密文分块计数与文件长度不一致。');

    const concurrency = streamConcurrency(header.algorithm);
    const metrics: PipelineMetrics = {
      readBytes: 0,
      readMs: 0,
      cryptoBytes: 0,
      cryptoMs: 0,
      writeBytes: 0,
      writeMs: 0,
      concurrency,
    };
    const report = progressReporter(meta.size, metrics, options.onProgress);
    let processed = 0;
    type PreparedPlainChunk = { plaintext: Uint8Array; plaintextLength: number; recordEnd: number };
    const fullRecordBytes = 4 + header.chunkSize + TAG_BYTES;
    const prepareChunk = async (chunk: number): Promise<PreparedPlainChunk> => {
      const chunkPlainOffset = chunk * header.chunkSize;
      const remaining = meta.size - chunkPlainOffset;
      const plaintextLength = Math.min(header.chunkSize, remaining);
      const encryptedLength = plaintextLength + TAG_BYTES;
      const cursor = metaEnd + chunk * fullRecordBytes;
      const recordEnd = cursor + 4 + encryptedLength;
      if (recordEnd > file.size) throw new Error('CRYPTA 密文被截断。');
      let lengthField: Uint8Array;
      let ciphertext: Uint8Array;
      const readStarted = performance.now();
      try {
        const [lengthBuffer, ciphertextBuffer] = await Promise.all([
          file.slice(cursor, cursor + 4).arrayBuffer(),
          file.slice(cursor + 4, recordEnd).arrayBuffer(),
        ]);
        lengthField = new Uint8Array(lengthBuffer);
        ciphertext = new Uint8Array(ciphertextBuffer);
      } catch (error) {
        throw describeFileSystemError(error, 'read');
      }
      metrics.readBytes += lengthField.byteLength + ciphertext.byteLength;
      metrics.readMs += performance.now() - readStarted;
      if (readU32(lengthField) !== encryptedLength) throw new Error('CRYPTA 分块记录长度被修改。');
      const index = chunk + 1;
      let plaintext: Uint8Array;
      const cryptoStarted = performance.now();
      try {
        plaintext = await cipher.decrypt(
          ciphertext,
          recordNonce(index),
          recordAad(prefix, 1, index, plaintextLength),
        );
      } catch {
        throw new Error(`第 ${index.toLocaleString()} 个分块认证失败：密钥/口令错误或密文已被修改。`);
      }
      metrics.cryptoBytes += plaintextLength;
      metrics.cryptoMs += performance.now() - cryptoStarted;
      return { plaintext, plaintextLength, recordEnd };
    };

    const inFlight = new Map<number, Promise<PreparedPlainChunk>>();
    const schedule = (chunk: number) => {
      if (chunk < meta.chunks) inFlight.set(chunk, prepareChunk(chunk));
    };
    for (let chunk = 0; chunk < Math.min(concurrency, meta.chunks); chunk += 1) schedule(chunk);

    let finalRecordEnd = metaEnd;
    for (let chunk = 0; chunk < meta.chunks; chunk += 1) {
      assertNotCancelled(options.shouldCancel);
      const prepared = await inFlight.get(chunk)!;
      inFlight.delete(chunk);
      schedule(chunk + concurrency);
      const writeStarted = performance.now();
      try {
        await writable.write(prepared.plaintext);
      } catch (error) {
        throw describeFileSystemError(error, 'write');
      }
      metrics.writeBytes += prepared.plaintext.byteLength;
      metrics.writeMs += performance.now() - writeStarted;
      finalRecordEnd = prepared.recordEnd;
      processed += prepared.plaintextLength;
      report(processed);
    }
    if (processed !== meta.size) throw new Error('解密后的文件长度不完整。');
    if (finalRecordEnd !== file.size) throw new Error('CRYPTA 密文末尾包含未认证的额外数据。');
    try {
      await writable.close();
    } catch (error) {
      throw describeFileSystemError(error, 'close');
    }
    const exportFile = await destination.finalize();
    return {
      ...meta,
      algorithm: header.algorithm,
      savedAs: destination.name,
      exportFile,
      storage: destination.storage,
      cleanup: destination.storage === 'opfs' ? destination.cleanup : undefined,
    };
  } catch (error) {
    await writable.abort(error).catch(() => undefined);
    throw error;
  } finally {
    fileKey?.fill(0);
    masterKey?.fill(0);
  }
}
