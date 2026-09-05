/// <reference lib="webworker" />

import {
  MAX_META_BYTES,
  STREAM_CHUNK_BYTES,
  StreamUserCancelledError,
  TAG_BYTES,
  createCipher,
  createFileSalt,
  createOpfsTempName,
  createProgressReporter,
  decodeStreamMetaBytes,
  deriveFileKey,
  encodeStreamHeader,
  encodeStreamMetaBytes,
  parseStreamMeta,
  prepareOpfsTempDirectory,
  readStreamPrefix,
  readU32,
  recordAad,
  recordNonce,
  resolveDecryptionKey,
  resolveEncryptionKey,
  runBoundedPipeline,
  u32,
  zeroMetrics,
  type AlgorithmId,
  type KeyDerivationInfo,
  type StreamHeader,
  type StreamMeta,
  type StreamProgress,
} from './streamCore.ts';
import { bytesToArrayBuffer, type PayloadMeta } from './crypto.ts';

interface StartEncryptMessage {
  type: 'start';
  operation: 'encrypt';
  file: File;
  algorithm: AlgorithmId;
  rawKey?: Uint8Array;
  passphrase?: string;
  keyDerivation?: KeyDerivationInfo;
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

function kdfProgress(progress: StreamProgress) {
  post('progress', { progress });
}

function checkCancelled() {
  if (cancelled) throw new DOMException('操作已由用户停止。', 'AbortError');
}

function concurrencyFor(algorithm: AlgorithmId): number {
  if (algorithm !== 'AES-256-GCM') return 1;
  return (navigator.hardwareConcurrency || 4) >= 4 ? 2 : 1;
}

async function openWriter(expectedBytes: number): Promise<{
  writer: Writer;
  root: FileSystemDirectoryHandle;
  handle: FileSystemFileHandle;
  tempName: string;
}> {
  const root = await prepareOpfsTempDirectory(expectedBytes);
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
              try { access.close(); } catch { /* 已关闭 / already closed */ }
            }
            await root.removeEntry(tempName).catch(() => undefined);
          },
        },
      };
    } catch {
      // 部分移动端实现先暴露 createSyncAccessHandle()，实际却拿不到首个 OPFS 锁；此时回退安全：
      // 尚未写入载荷字节，createWritable() 仍产出相同 CRYPTA V2 格式，只是避免首次运行硬失败。
      // Some mobile implementations expose createSyncAccessHandle() before the first OPFS lock
      // is obtainable. Falling back is safe: no payload written yet, and createWritable()
      // preserves the same CRYPTA V2 format while avoiding a first-run hard failure.
    }
  }

  let writable: Awaited<ReturnType<FileSystemFileHandle['createWritable']>>;
  try {
    writable = await handle.createWritable();
  } catch (error) {
    // 打开 writer 失败时文件可能已存在 / The file may already exist even when opening its writer fails.
    await root.removeEntry(tempName).catch(() => undefined);
    throw error;
  }
  let closed = false;
  return {
    root,
    handle,
    tempName,
    writer: {
      write: async (data) => writable.write(bytesToArrayBuffer(data)),
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

async function encrypt(message: StartEncryptMessage): Promise<WorkerResult> {
  const destination = await openWriter(message.expectedBytes);
  let masterKey: Uint8Array | undefined;
  let fileKey: Uint8Array | undefined;
  try {
    checkCancelled();
    const resolved = await resolveEncryptionKey(
      { rawKey: message.rawKey, passphrase: message.passphrase, keyDerivation: message.keyDerivation },
      kdfProgress,
    );
    masterKey = resolved.key;
    const fileSalt = createFileSalt();
    fileKey = deriveFileKey(masterKey, fileSalt);
    const chunks = Math.ceil(message.file.size / STREAM_CHUNK_BYTES);
    if (chunks > 0xffff_fffe) throw new Error('文件过大，超出当前 CRYPTA 流式格式容量。');
    const header: StreamHeader = {
      version: 2,
      algorithm: message.algorithm,
      chunkSize: STREAM_CHUNK_BYTES,
      fileSalt,
      keyDerivation: resolved.kdf,
    };
    const { prefix } = encodeStreamHeader(header);
    const meta: StreamMeta = {
      kind: 'file',
      name: message.file.name,
      mime: message.file.type || 'application/octet-stream',
      size: message.file.size,
      createdAt: new Date().toISOString(),
      chunks,
    };
    const metaBytes = encodeStreamMetaBytes(meta);
    const cipher = await createCipher(message.algorithm, fileKey);
    const encryptedMeta = await cipher.encrypt(metaBytes, recordNonce(0), recordAad(prefix, 0, 0, metaBytes.byteLength));
    await destination.writer.write(prefix);
    await destination.writer.write(u32(encryptedMeta.byteLength));
    await destination.writer.write(encryptedMeta);

    const concurrency = concurrencyFor(message.algorithm);
    const metrics = zeroMetrics(concurrency);
    const report = createProgressReporter(message.file.size, metrics, (progress) => post('progress', { progress }));
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
    let processed = 0;
    await runBoundedPipeline(
      chunks,
      concurrency,
      prepare,
      async (_index, prepared) => {
        const writeStarted = performance.now();
        await destination.writer.write(u32(prepared.encrypted.byteLength));
        await destination.writer.write(prepared.encrypted);
        metrics.writeBytes += prepared.encrypted.byteLength + 4;
        metrics.writeMs += performance.now() - writeStarted;
        processed += prepared.plaintextLength;
        report(processed);
      },
      () => cancelled,
    );
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
  const destination = await openWriter(message.expectedBytes);
  let masterKey: Uint8Array | undefined;
  let fileKey: Uint8Array | undefined;
  try {
    const { header, prefix, offset: prefixOffset } = await readStreamPrefix(message.file);
    masterKey = await resolveDecryptionKey(
      header.keyDerivation,
      { rawKey: message.rawKey, passphrase: message.passphrase },
      kdfProgress,
    );
    fileKey = deriveFileKey(masterKey, header.fileSalt);
    const cipher = await createCipher(header.algorithm, fileKey);

    if (prefixOffset + 4 > message.file.size) throw new Error('CRYPTA 文件缺少受保护元数据。');
    const lengthBytes = new Uint8Array(await message.file.slice(prefixOffset, prefixOffset + 4).arrayBuffer());
    const encryptedMetaLength = readU32(lengthBytes);
    if (encryptedMetaLength <= TAG_BYTES || encryptedMetaLength > MAX_META_BYTES) throw new Error('CRYPTA 元数据记录长度无效。');
    const metaEnd = prefixOffset + 4 + encryptedMetaLength;
    if (metaEnd > message.file.size) throw new Error('CRYPTA 元数据记录已截断。');
    const encryptedMeta = new Uint8Array(await message.file.slice(prefixOffset + 4, metaEnd).arrayBuffer());
    let metaBytes: Uint8Array;
    try {
      metaBytes = await cipher.decrypt(encryptedMeta, recordNonce(0), recordAad(prefix, 0, 0, encryptedMetaLength - TAG_BYTES));
    } catch {
      throw new Error('解密失败：密钥/口令错误，或密文头部已被修改。');
    }
    const meta = parseStreamMeta(decodeStreamMetaBytes(metaBytes));
    if (Math.ceil(meta.size / header.chunkSize) !== meta.chunks) throw new Error('密文分块计数与文件长度不一致。');

    const concurrency = concurrencyFor(header.algorithm);
    const metrics = zeroMetrics(concurrency);
    const report = createProgressReporter(meta.size, metrics, (progress) => post('progress', { progress }));
    const fullRecordBytes = 4 + header.chunkSize + TAG_BYTES;
    type Prepared = { plaintext: Uint8Array; plaintextLength: number; recordEnd: number };
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
      return { plaintext, plaintextLength, recordEnd };
    };

    let processed = 0;
    let finalEnd = metaEnd;
    await runBoundedPipeline(
      meta.chunks,
      concurrency,
      prepare,
      async (_index, prepared) => {
        const writeStarted = performance.now();
        await destination.writer.write(prepared.plaintext);
        metrics.writeBytes += prepared.plaintext.byteLength;
        metrics.writeMs += performance.now() - writeStarted;
        processed += prepared.plaintextLength;
        finalEnd = prepared.recordEnd;
        report(processed);
      },
      () => cancelled,
    );
    if (processed !== meta.size) throw new Error('解密后的文件长度不完整。');
    if (finalEnd !== message.file.size) throw new Error('CRYPTA 密文末尾包含未认证的额外数据。');
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
      const isUserCancel = error instanceof StreamUserCancelledError
        || (error instanceof DOMException && error.name === 'AbortError' && cancelled);
      post('error', {
        error: {
          name: isUserCancel ? 'StreamUserCancelledError' : error instanceof Error ? error.name : 'Error',
          message: isUserCancel ? '操作已由用户停止。' : error instanceof Error ? error.message : '流式处理失败。',
        },
      });
    });
};

post('ready');
