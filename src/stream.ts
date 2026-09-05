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

// App.tsx 直接从本模块导入以下符号，保持导出面不变。
// Re-exported so App.tsx keeps importing everything from './stream'.
export { STREAM_CHUNK_BYTES, StreamUserCancelledError, type StreamProgress };

export const STREAM_THRESHOLD_BYTES = 64 * 1024 * 1024;

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

async function openOpfsDestination(suggestedName: string, expectedBytes: number): Promise<StreamDestination> {
  const root = await prepareOpfsTempDirectory(expectedBytes);
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
    keyDerivation?: KeyDerivationInfo;
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

function assertNotCancelled(shouldCancel?: () => boolean) {
  if (shouldCancel?.()) throw new StreamUserCancelledError();
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
      keyDerivation: options.keyDerivation,
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
    const resolved = await resolveEncryptionKey(options, options.onProgress);
    masterKey = resolved.key;
    const { kdf } = resolved;
    assertNotCancelled(options.shouldCancel);

    const fileSalt = createFileSalt();
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
    const { prefix } = encodeStreamHeader(header);
    const meta: StreamMeta = {
      kind: 'file',
      name: file.name,
      mime: file.type || 'application/octet-stream',
      size: file.size,
      createdAt: new Date().toISOString(),
      chunks,
    };
    const metaBytes = encodeStreamMetaBytes(meta);
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
    const metrics = zeroMetrics(concurrency);
    const report = createProgressReporter(file.size, metrics, options.onProgress);
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
    await runBoundedPipeline(
      chunks,
      concurrency,
      prepareChunk,
      async (_index, prepared) => {
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
      },
      options.shouldCancel,
    );
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
    masterKey = await resolveDecryptionKey(header.keyDerivation, options, options.onProgress);
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
    const meta = parseStreamMeta(await decodeStreamMetaBytes(metaBytes));
    const expectedChunks = Math.ceil(meta.size / header.chunkSize);
    if (expectedChunks !== meta.chunks) throw new Error('密文分块计数与文件长度不一致。');

    const concurrency = streamConcurrency(header.algorithm);
    const metrics = zeroMetrics(concurrency);
    const report = createProgressReporter(meta.size, metrics, options.onProgress);
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

    let finalRecordEnd = metaEnd;
    await runBoundedPipeline(
      meta.chunks,
      concurrency,
      prepareChunk,
      async (_index, prepared) => {
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
      },
      options.shouldCancel,
    );
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
