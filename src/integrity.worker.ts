import {
  createBLAKE2b,
  createBLAKE3,
  createMD5,
  createSHA1,
  createSHA256,
  createSHA3,
  createSHA512,
  type IHasher,
} from 'hash-wasm';
import { Blake3Hasher, init as initBlake3 } from '@fuzdev/blake3_wasm';
import { bytesToHex } from '@noble/hashes/utils.js';
import { type AlgorithmId } from './integrity';

const CHUNK_BYTES = 8 * 1024 * 1024;
// 两个 8 MiB 读请求足以覆盖单块 SIMD BLAKE3 计算时间；更多并发在同一磁盘上
// 容易从顺序读取退化为多文件竞争。全局并行度由 IntegrityChecker 自适应控制。
const READ_AHEAD = 2;

type HashMessage = {
  type: 'hash';
  index: number;
  file: File;
  algorithms: AlgorithmId[];
};

type CancelMessage = { type: 'cancel' };

let cancelled = false;
let active = false;

/**
 * 每个 Dedicated Worker 只实例化一次各算法的 WASM 模块，文件之间通过 init() 复用。
 * 这对包含大量小文件的目录尤其重要：避免反复编译 / 实例化 WebAssembly。
 */
const hasherCache = new Map<AlgorithmId, Promise<IHasher>>();
let blake3Ready: Promise<void> | undefined;

type ActiveHasher = {
  id: AlgorithmId;
  backend: string;
  update(data: Uint8Array): void;
  digestHex(): string;
  dispose?(): void;
};

function createHasher(id: AlgorithmId): Promise<IHasher> {
  switch (id) {
    case 'MD5': return createMD5();
    case 'SHA-1': return createSHA1();
    case 'SHA-256': return createSHA256();
    case 'SHA-512': return createSHA512();
    case 'SHA3-256': return createSHA3(256);
    case 'SHA3-512': return createSHA3(512);
    case 'BLAKE2b-512': return createBLAKE2b(512);
    case 'BLAKE3': return createBLAKE3(256);
  }
}

async function acquireHasher(id: AlgorithmId): Promise<IHasher> {
  let hasher = hasherCache.get(id);
  if (!hasher) {
    hasher = createHasher(id);
    hasherCache.set(id, hasher);
  }
  return (await hasher).init();
}

async function acquireActiveHasher(id: AlgorithmId): Promise<ActiveHasher> {
  if (id === 'BLAKE3') {
    try {
      blake3Ready ??= initBlake3();
      await blake3Ready;
      const hasher = new Blake3Hasher();
      return {
        id,
        backend: 'SIMD Rust/WASM',
        update: (data) => hasher.update(data),
        digestHex: () => bytesToHex(hasher.finalize()),
        dispose: () => hasher.free(),
      };
    } catch {
      // Older WebViews without WASM SIMD support still get the proven scalar
      // WASM backend instead of losing integrity checking altogether.
    }
  }

  const hasher = await acquireHasher(id);
  return {
    id,
    backend: id === 'BLAKE3' ? 'WASM fallback' : 'WASM',
    update: (data) => { hasher.update(data); },
    digestHex: () => hasher.digest('hex'),
  };
}

function post(message: unknown) {
  self.postMessage(message);
}

async function hashFile(index: number, file: File, algorithms: AlgorithmId[]) {
  if (active) return;
  active = true;
  cancelled = false;
  const hashers = await Promise.all(algorithms.map(acquireActiveHasher));
  if (hashers.length === 0) {
    post({ type: 'file-error', index, message: '未选择任何哈希算法。' });
    active = false;
    return;
  }

  let fileProcessed = 0;
  let lastProgressAt = 0;
  const startedAt = performance.now();
  let hashMs = 0;
  let ioWaitMs = 0;
  const backend = hashers.map((hasher) => `${hasher.id}: ${hasher.backend}`).join(' · ');
  const useStream = typeof file.stream === 'function';
  const ioBackend = useStream ? 'File.stream' : 'Blob.slice';
  post({
    type: 'file-start',
    index,
    backend: `${backend} · I/O: ${ioBackend}`,
    chunkBytes: CHUNK_BYTES,
    readAhead: useStream ? 1 : READ_AHEAD,
  });

  try {
    const emitProgress = () => {
      const now = performance.now();
      if (now - lastProgressAt < 80 && fileProcessed !== file.size) return;
      lastProgressAt = now;
      const elapsedMs = Math.max(now - startedAt, 0.001);
      post({
        type: 'progress',
        index,
        fileProcessed,
        fileSize: file.size,
        backend: `${backend} · I/O: ${ioBackend}`,
        hashBytesPerSecond: hashMs > 0 ? fileProcessed / (hashMs / 1000) : 0,
        pipelineBytesPerSecond: fileProcessed / (elapsedMs / 1000),
        ioWaitRatio: Math.min(Math.max(ioWaitMs / elapsedMs, 0), 1),
      });
    };

    if (useStream) {
      // Prefer one continuous sequential read. Repeated Blob slicing is noticeably
      // slower on some sandboxed filesystems/document providers even when reads are
      // prefetched. BLAKE3 has ample CPU headroom for the smaller stream chunks.
      const reader = file.stream().getReader();
      try {
        while (!cancelled) {
          const waitStartedAt = performance.now();
          const { done, value } = await reader.read();
          ioWaitMs += performance.now() - waitStartedAt;
          if (done) break;
          if (!value || value.byteLength === 0) continue;

          const hashStartedAt = performance.now();
          for (const hasher of hashers) hasher.update(value);
          hashMs += performance.now() - hashStartedAt;
          fileProcessed += value.byteLength;
          emitProgress();
        }
      } finally {
        if (cancelled) await reader.cancel().catch(() => undefined);
        reader.releaseLock();
      }
    } else {
      const readChunk = (offset: number) => {
        const end = Math.min(offset + CHUNK_BYTES, file.size);
        return file.slice(offset, end).arrayBuffer().then((buffer) => ({
          offset,
          chunk: new Uint8Array(buffer),
        }));
      };

      const pending: Array<Promise<{ offset: number; chunk: Uint8Array }>> = [];
      let nextReadOffset = 0;
      const fillReadAhead = () => {
        while (pending.length < READ_AHEAD && nextReadOffset < file.size) {
          pending.push(readChunk(nextReadOffset));
          nextReadOffset += CHUNK_BYTES;
        }
      };
      fillReadAhead();

      while (pending.length > 0) {
        if (cancelled) break;
        const waitStartedAt = performance.now();
        const { chunk } = await pending.shift()!;
        ioWaitMs += performance.now() - waitStartedAt;
        if (cancelled) break;
        fillReadAhead();

        const hashStartedAt = performance.now();
        for (const hasher of hashers) hasher.update(chunk);
        hashMs += performance.now() - hashStartedAt;
        fileProcessed += chunk.byteLength;
        emitProgress();
      }
    }

    if (cancelled) {
      post({ type: 'cancelled', index });
      return;
    }

    const hashes: Record<string, string> = {};
    for (const hasher of hashers) hashes[hasher.id] = hasher.digestHex();
    post({ type: 'file', index, hashes });
  } catch (error) {
    post({
      type: 'file-error',
      index,
      message: error instanceof Error ? error.message : '哈希计算失败。',
    });
  } finally {
    for (const hasher of hashers) hasher.dispose?.();
    active = false;
  }
}

self.onmessage = (event: MessageEvent<HashMessage | CancelMessage>) => {
  if (event.data.type === 'cancel') {
    cancelled = true;
    return;
  }

  void hashFile(event.data.index, event.data.file, event.data.algorithms);
};

post({ type: 'ready' });
