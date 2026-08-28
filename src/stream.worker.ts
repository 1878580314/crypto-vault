/// <reference lib="webworker" />

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

const STREAM_CHUNK_BYTES = 16 * 1024 * 1024;
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

interface StartEncryptMessage {
  type: 'start';
  operation: 'encrypt';
  file: File;
  algorithm: AlgorithmId;
  rawKey?: Uint8Array;
  passphrase?: string;
  suggestedName: string;
  expectedBytes: number;
}

interface StartDecryptMessage {
  type: 'start';
  operation: 'decrypt';
  file: File;
  rawKey?: Uint8Array;
  passphrase?: string;
  suggestedName: string;
  expectedBytes: number;
}

type StartMessage = StartEncryptMessage | StartDecryptMessage;
type IncomingMessage = StartMessage | { type: 'cancel' };

interface PipelineMetrics {
  readBytes: number;
  readMs: number;
  cryptoBytes: number;
  cryptoMs: number;
  writeBytes: number;
  writeMs: number;
  concurrency: number;
}

interface WorkerResult extends PayloadMeta {
  savedAs: string;
  tempName: string;
  exportFile: File;
  storage: 'opfs';
}

interface Writer {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(): Promise<void>;
}

let cancelled = false;

function post(type: string, payload: Record<string, unknown> = {}) {
  self.postMessage({ type, ...payload });
}

function checkCancelled() {
  if (cancelled) throw new DOMException('操作已由用户停止。', 'AbortError');
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
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
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
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

function parseHeader(value: unknown): StreamHeader {
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

function parseMeta(value: unknown): StreamMeta {
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

function deriveFileKey(masterKey: Uint8Array, fileSalt: Uint8Array): Uint8Array {
  return hkdf(sha256, masterKey, fileSalt, STREAM_KEY_INFO, 32);
}

async function createCipher(algorithm: AlgorithmId, key: Uint8Array) {
  if (algorithm === 'AES-256-GCM') {
    const cryptoKey = await crypto.subtle.importKey('raw', asArrayBuffer(key), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return {
      encrypt: async (plaintext: Uint8Array, nonce: Uint8Array, aad: Uint8Array) => new Uint8Array(
        await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: asArrayBuffer(nonce), additionalData: asArrayBuffer(aad), tagLength: 128 },
          cryptoKey,
          asArrayBuffer(plaintext),
        ),
      ),
      decrypt: async (ciphertext: Uint8Array, nonce: Uint8Array, aad: Uint8Array) => new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: asArrayBuffer(nonce), additionalData: asArrayBuffer(aad), tagLength: 128 },
          cryptoKey,
          asArrayBuffer(ciphertext),
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

async function resolveEncryptionKey(message: StartEncryptMessage): Promise<{ key: Uint8Array; kdf: KeyDerivationInfo }> {
  if (message.passphrase !== undefined) {
    const kdf = createPassphraseKdf();
    const key = await derivePassphraseKey(message.passphrase, kdf, (ratio) => post('progress', {
      progress: { processed: 0, total: 0, ratio, bytesPerSecond: 0, phase: 'kdf' },
    }));
    return { key, kdf };
  }
  if (!message.rawKey) throw new Error('缺少 256 位密钥。');
  return { key: message.rawKey.slice(), kdf: { type: 'raw' } };
}

async function resolveDecryptionKey(kdf: KeyDerivationInfo, message: StartDecryptMessage): Promise<Uint8Array> {
  if (kdf.type === 'argon2id') {
    if (message.passphrase === undefined) throw new Error('该密文需要文本口令。');
    return derivePassphraseKey(message.passphrase, kdf, (ratio) => post('progress', {
      progress: { processed: 0, total: 0, ratio, bytesPerSecond: 0, phase: 'kdf' },
    }));
  }
  if (!message.rawKey) throw new Error('该密文需要 256 位原始密钥。');
  return message.rawKey.slice();
}

function concurrencyFor(algorithm: AlgorithmId): number {
  if (algorithm !== 'AES-256-GCM') return 1;
  return (navigator.hardwareConcurrency || 4) >= 4 ? 2 : 1;
}

function stageRate(bytes: number, milliseconds: number): number {
  return milliseconds > 0 ? bytes / (milliseconds / 1000) : 0;
}

function progressReporter(total: number, metrics: PipelineMetrics) {
  const started = performance.now();
  return (processed: number) => {
    const seconds = Math.max((performance.now() - started) / 1000, 0.001);
    post('progress', {
      progress: {
        processed,
        total,
        ratio: total === 0 ? 1 : Math.min(processed / total, 1),
        bytesPerSecond: processed / seconds,
        readBytesPerSecond: stageRate(metrics.readBytes, metrics.readMs),
        cryptoBytesPerSecond: stageRate(metrics.cryptoBytes, metrics.cryptoMs),
        writeBytesPerSecond: stageRate(metrics.writeBytes, metrics.writeMs),
        concurrency: metrics.concurrency,
        phase: 'data',
      },
    });
  };
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
        // A missing/invalid timestamp is not enough evidence to reclaim a file.
        if (!Number.isFinite(file.lastModified) || file.lastModified <= 0 || file.lastModified > cutoff) continue;
        await root.removeEntry(name).catch(() => undefined);
      } catch {
        // An active/locked file or an implementation without getFile() remains untouched.
      }
    }
  } catch {
    // Directory iteration is optional on some implementations.
  }
}

async function ensureCapacity(requiredBytes: number) {
  const estimate = await navigator.storage.estimate();
  if (!estimate.quota) return;
  const available = Math.max(0, estimate.quota - (estimate.usage ?? 0));
  const requiredWithHeadroom = Math.ceil(requiredBytes * 1.08 + 16 * 1024 * 1024);
  if (available < requiredWithHeadroom) {
    throw new Error(`浏览器临时存储空间不足：至少还需要约 ${Math.ceil(requiredWithHeadroom / 1024 / 1024)} MiB 可用空间。`);
  }
}

async function openWriter(suggestedName: string, expectedBytes: number): Promise<{
  writer: Writer;
  root: FileSystemDirectoryHandle;
  handle: FileSystemFileHandle;
  tempName: string;
}> {
  const root = await navigator.storage.getDirectory();
  // Reclaim only files untouched for at least a day, then measure the space that remains.
  await cleanupExpiredOpfsTemps(root);
  await ensureCapacity(expectedBytes);
  const tempName = createOpfsTempName();
  let handle: FileSystemFileHandle;
  try {
    handle = await root.getFileHandle(tempName, { create: true });
  } catch (error) {
    await root.removeEntry(tempName).catch(() => undefined);
    throw error;
  }
  const syncFactory = (handle as FileSystemFileHandle & {
    createSyncAccessHandle?: () => Promise<FileSystemSyncAccessHandle>;
  }).createSyncAccessHandle;

  if (typeof syncFactory === 'function') {
    try {
      const access = await syncFactory.call(handle);
      let offset = 0;
      let closed = false;
      return {
        root,
        handle,
        tempName,
        writer: {
          write: async (data) => {
            const written = access.write(data, { at: offset });
            if (written !== data.byteLength) throw new Error('OPFS 写入不完整。');
            offset += written;
          },
          close: async () => {
            access.flush();
            access.close();
            closed = true;
          },
          abort: async () => {
            if (!closed) {
              try { access.close(); } catch { /* already closed */ }
            }
            await root.removeEntry(tempName).catch(() => undefined);
          },
        },
      };
    } catch {
      // Some mobile implementations expose createSyncAccessHandle() before the
      // first OPFS lock is actually obtainable. Falling back here is safe: no
      // payload bytes have been written yet, and createWritable() preserves the
      // same CRYPTA V2 format while avoiding a first-run hard failure.
    }
  }

  let writable: Awaited<ReturnType<FileSystemFileHandle['createWritable']>>;
  try {
    writable = await handle.createWritable();
  } catch (error) {
    // The file may already exist even when opening its writer fails.
    await root.removeEntry(tempName).catch(() => undefined);
    throw error;
  }
  let closed = false;
  return {
    root,
    handle,
    tempName,
    writer: {
      write: async (data) => writable.write(asArrayBuffer(data)),
      close: async () => {
        await writable.close();
        closed = true;
      },
      abort: async () => {
        if (!closed) await writable.abort().catch(() => undefined);
        await root.removeEntry(tempName).catch(() => undefined);
      },
    },
  };
}

async function readPrefix(file: File): Promise<{ header: StreamHeader; prefix: Uint8Array; offset: number }> {
  const fixed = new Uint8Array(await file.slice(0, STREAM_MAGIC.byteLength + 4).arrayBuffer());
  if (!equalBytes(fixed.subarray(0, STREAM_MAGIC.byteLength), STREAM_MAGIC)) throw new Error('文件不是 CRYPTA V2 流式密文。');
  const headerLength = readU32(fixed, STREAM_MAGIC.byteLength);
  if (headerLength === 0 || headerLength > MAX_HEADER_BYTES) throw new Error('CRYPTA 流式头部长度无效。');
  const prefixLength = STREAM_MAGIC.byteLength + 4 + headerLength;
  if (prefixLength > file.size) throw new Error('CRYPTA 流式头部已截断。');
  const prefix = new Uint8Array(await file.slice(0, prefixLength).arrayBuffer());
  return { header: parseHeader(decode(prefix.subarray(STREAM_MAGIC.byteLength + 4))), prefix, offset: prefixLength };
}

async function encrypt(message: StartEncryptMessage): Promise<WorkerResult> {
  const destination = await openWriter(message.suggestedName, message.expectedBytes);
  let masterKey: Uint8Array | undefined;
  let fileKey: Uint8Array | undefined;
  try {
    checkCancelled();
    const resolved = await resolveEncryptionKey(message);
    masterKey = resolved.key;
    const fileSalt = crypto.getRandomValues(new Uint8Array(FILE_SALT_BYTES));
    fileKey = deriveFileKey(masterKey, fileSalt);
    const chunks = Math.ceil(message.file.size / STREAM_CHUNK_BYTES);
    const header: StreamHeader = {
      version: 2,
      algorithm: message.algorithm,
      chunkSize: STREAM_CHUNK_BYTES,
      fileSalt,
      keyDerivation: resolved.kdf,
    };
    const headerBytes = encode(header);
    const prefix = concat(STREAM_MAGIC, u32(headerBytes.byteLength), headerBytes);
    const meta: StreamMeta = {
      kind: 'file',
      name: message.file.name,
      mime: message.file.type || 'application/octet-stream',
      size: message.file.size,
      createdAt: new Date().toISOString(),
      chunks,
    };
    const metaBytes = encode(meta);
    const cipher = await createCipher(message.algorithm, fileKey);
    const encryptedMeta = await cipher.encrypt(metaBytes, recordNonce(0), recordAad(prefix, 0, 0, metaBytes.byteLength));
    await destination.writer.write(prefix);
    await destination.writer.write(u32(encryptedMeta.byteLength));
    await destination.writer.write(encryptedMeta);

    const concurrency = concurrencyFor(message.algorithm);
    const metrics: PipelineMetrics = { readBytes: 0, readMs: 0, cryptoBytes: 0, cryptoMs: 0, writeBytes: 0, writeMs: 0, concurrency };
    const report = progressReporter(message.file.size, metrics);
    type Prepared = { encrypted: Uint8Array; plaintextLength: number };
    const prepare = async (chunk: number): Promise<Prepared> => {
      const start = chunk * STREAM_CHUNK_BYTES;
      const end = Math.min(start + STREAM_CHUNK_BYTES, message.file.size);
      const readStarted = performance.now();
      const buffer = await message.file.slice(start, end).arrayBuffer();
      const plaintext = new Uint8Array(buffer);
      metrics.readBytes += plaintext.byteLength;
      metrics.readMs += performance.now() - readStarted;
      const index = chunk + 1;
      const cryptoStarted = performance.now();
      const encrypted = await cipher.encrypt(plaintext, recordNonce(index), recordAad(prefix, 1, index, plaintext.byteLength));
      metrics.cryptoBytes += plaintext.byteLength;
      metrics.cryptoMs += performance.now() - cryptoStarted;
      return { encrypted, plaintextLength: plaintext.byteLength };
    };
    const queue = new Map<number, Promise<Prepared>>();
    const schedule = (chunk: number) => { if (chunk < chunks) queue.set(chunk, prepare(chunk)); };
    for (let chunk = 0; chunk < Math.min(chunks, concurrency); chunk += 1) schedule(chunk);

    let processed = 0;
    for (let chunk = 0; chunk < chunks; chunk += 1) {
      checkCancelled();
      const prepared = await queue.get(chunk)!;
      queue.delete(chunk);
      schedule(chunk + concurrency);
      const writeStarted = performance.now();
      await destination.writer.write(u32(prepared.encrypted.byteLength));
      await destination.writer.write(prepared.encrypted);
      metrics.writeBytes += prepared.encrypted.byteLength + 4;
      metrics.writeMs += performance.now() - writeStarted;
      processed += prepared.plaintextLength;
      report(processed);
    }
    await destination.writer.close();
    const exportFile = await destination.handle.getFile();
    return { ...meta, algorithm: message.algorithm, savedAs: message.suggestedName, tempName: destination.tempName, exportFile, storage: 'opfs' };
  } catch (error) {
    await destination.writer.abort().catch(() => undefined);
    throw error;
  } finally {
    fileKey?.fill(0);
    masterKey?.fill(0);
  }
}

async function decrypt(message: StartDecryptMessage): Promise<WorkerResult> {
  const destination = await openWriter(message.suggestedName, message.expectedBytes);
  let masterKey: Uint8Array | undefined;
  let fileKey: Uint8Array | undefined;
  try {
    const { header, prefix, offset: prefixOffset } = await readPrefix(message.file);
    masterKey = await resolveDecryptionKey(header.keyDerivation, message);
    fileKey = deriveFileKey(masterKey, header.fileSalt);
    const cipher = await createCipher(header.algorithm, fileKey);

    const lengthBytes = new Uint8Array(await message.file.slice(prefixOffset, prefixOffset + 4).arrayBuffer());
    const encryptedMetaLength = readU32(lengthBytes);
    if (encryptedMetaLength <= TAG_BYTES || encryptedMetaLength > MAX_META_BYTES) throw new Error('CRYPTA 元数据记录长度无效。');
    const metaEnd = prefixOffset + 4 + encryptedMetaLength;
    const encryptedMeta = new Uint8Array(await message.file.slice(prefixOffset + 4, metaEnd).arrayBuffer());
    let metaBytes: Uint8Array;
    try {
      metaBytes = await cipher.decrypt(encryptedMeta, recordNonce(0), recordAad(prefix, 0, 0, encryptedMetaLength - TAG_BYTES));
    } catch {
      throw new Error('解密失败：密钥/口令错误，或密文头部已被修改。');
    }
    const meta = parseMeta(decode(metaBytes));
    if (Math.ceil(meta.size / header.chunkSize) !== meta.chunks) throw new Error('密文分块计数与文件长度不一致。');

    const concurrency = concurrencyFor(header.algorithm);
    const metrics: PipelineMetrics = { readBytes: 0, readMs: 0, cryptoBytes: 0, cryptoMs: 0, writeBytes: 0, writeMs: 0, concurrency };
    const report = progressReporter(meta.size, metrics);
    const fullRecordBytes = 4 + header.chunkSize + TAG_BYTES;
    type Prepared = { plaintext: Uint8Array; recordEnd: number };
    const prepare = async (chunk: number): Promise<Prepared> => {
      const plainOffset = chunk * header.chunkSize;
      const plaintextLength = Math.min(header.chunkSize, meta.size - plainOffset);
      const encryptedLength = plaintextLength + TAG_BYTES;
      const cursor = metaEnd + chunk * fullRecordBytes;
      const recordEnd = cursor + 4 + encryptedLength;
      if (recordEnd > message.file.size) throw new Error('CRYPTA 密文被截断。');
      const readStarted = performance.now();
      const [lengthBuffer, ciphertextBuffer] = await Promise.all([
        message.file.slice(cursor, cursor + 4).arrayBuffer(),
        message.file.slice(cursor + 4, recordEnd).arrayBuffer(),
      ]);
      const lengthField = new Uint8Array(lengthBuffer);
      const ciphertext = new Uint8Array(ciphertextBuffer);
      metrics.readBytes += lengthField.byteLength + ciphertext.byteLength;
      metrics.readMs += performance.now() - readStarted;
      if (readU32(lengthField) !== encryptedLength) throw new Error('CRYPTA 分块记录长度被修改。');
      const index = chunk + 1;
      const cryptoStarted = performance.now();
      let plaintext: Uint8Array;
      try {
        plaintext = await cipher.decrypt(ciphertext, recordNonce(index), recordAad(prefix, 1, index, plaintextLength));
      } catch {
        throw new Error(`第 ${index.toLocaleString()} 个分块认证失败：密钥/口令错误或密文已被修改。`);
      }
      metrics.cryptoBytes += plaintextLength;
      metrics.cryptoMs += performance.now() - cryptoStarted;
      return { plaintext, recordEnd };
    };
    const queue = new Map<number, Promise<Prepared>>();
    const schedule = (chunk: number) => { if (chunk < meta.chunks) queue.set(chunk, prepare(chunk)); };
    for (let chunk = 0; chunk < Math.min(meta.chunks, concurrency); chunk += 1) schedule(chunk);

    let processed = 0;
    let finalEnd = metaEnd;
    for (let chunk = 0; chunk < meta.chunks; chunk += 1) {
      checkCancelled();
      const prepared = await queue.get(chunk)!;
      queue.delete(chunk);
      schedule(chunk + concurrency);
      const writeStarted = performance.now();
      await destination.writer.write(prepared.plaintext);
      metrics.writeBytes += prepared.plaintext.byteLength;
      metrics.writeMs += performance.now() - writeStarted;
      processed += prepared.plaintext.byteLength;
      finalEnd = prepared.recordEnd;
      report(processed);
    }
    if (processed !== meta.size || finalEnd !== message.file.size) throw new Error('CRYPTA 密文长度校验失败。');
    await destination.writer.close();
    const exportFile = await destination.handle.getFile();
    return { ...meta, algorithm: header.algorithm, savedAs: meta.name || message.suggestedName, tempName: destination.tempName, exportFile, storage: 'opfs' };
  } catch (error) {
    await destination.writer.abort().catch(() => undefined);
    throw error;
  } finally {
    fileKey?.fill(0);
    masterKey?.fill(0);
  }
}

self.onmessage = (event: MessageEvent<IncomingMessage>) => {
  if (event.data.type === 'cancel') {
    cancelled = true;
    return;
  }
  cancelled = false;
  const message = event.data;
  void (message.operation === 'encrypt' ? encrypt(message) : decrypt(message))
    .then((result) => post('done', { result }))
    .catch((error: unknown) => {
      const isUserCancel = error instanceof DOMException && error.name === 'AbortError' && cancelled;
      post('error', {
        error: {
          name: isUserCancel ? 'StreamUserCancelledError' : error instanceof Error ? error.name : 'Error',
          message: isUserCancel ? '操作已由用户停止。' : error instanceof Error ? error.message : '流式处理失败。',
        },
      });
    });
};

post('ready');
