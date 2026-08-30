import type { StreamTargetChunk } from 'mediabunny';

export const IMAGE_COMPRESSION_THRESHOLD_BYTES = 2 * 1024 * 1024;
export const VIDEO_COMPRESSION_THRESHOLD_BYTES = 12 * 1024 * 1024;

export interface PreparedImage {
  file: File;
  compressed: boolean;
  originalSize: number;
}

export interface VideoCompressionSession {
  mime: 'video/mp4';
  name: string;
  execute(
    writeAt: (position: number, chunk: Uint8Array) => Promise<void>,
    onProgress?: (ratio: number) => void,
  ): Promise<number>;
}

async function compressImageLocally(file: File, onProgress?: (ratio: number) => void): Promise<File> {
  if (typeof Worker === 'function' && typeof OffscreenCanvas === 'function') {
    try {
      return await new Promise<File>((resolve, reject) => {
        const worker = new Worker(new URL('./chat-image.worker.ts', import.meta.url), {
          type: 'module',
          name: 'crypta-chat-image-compressor',
        });
        const dispose = () => worker.terminate();
        worker.onerror = (event) => {
          dispose();
          reject(new Error(event.message || '图片压缩 Worker 运行失败。'));
        };
        worker.onmessage = (event: MessageEvent<{
          type: 'progress' | 'done' | 'error';
          progress?: number;
          file?: File;
          message?: string;
        }>) => {
          if (event.data.type === 'progress') {
            onProgress?.(Math.min(Math.max((event.data.progress ?? 0) / 100, 0), 1));
            return;
          }
          dispose();
          if (event.data.type === 'done' && event.data.file) resolve(event.data.file);
          else reject(new Error(event.data.message || '图片压缩失败。'));
        };
        worker.postMessage(file);
      });
    } catch {
      // 少数旧 Safari/WebView 组合虽暴露 Worker/OffscreenCanvas，但 worker 内 canvas 编码仍失败；回退到本地 UI 线程。
      // A few older Safari/WebView combinations expose Worker/OffscreenCanvas but still
      // fail canvas encoding in workers; fall through to the local UI thread.
    }
  }

  const { default: imageCompression } = await import('browser-image-compression');
  return imageCompression(file, {
    maxSizeMB: IMAGE_COMPRESSION_THRESHOLD_BYTES / 1024 / 1024,
    maxWidthOrHeight: 2560,
    initialQuality: 0.86,
    alwaysKeepResolution: false,
    preserveExif: false,
    // 库自带 worker 默认走 jsDelivr CDN libURL；私密工具必须零外部请求，改用上方打包的专用 worker。
    // The library's own worker defaults to a jsDelivr libURL; keep this privacy-sensitive
    // tool fully self-contained via our dedicated bundled worker above.
    useWebWorker: false,
    onProgress: (percent) => onProgress?.(Math.min(Math.max(percent / 100, 0), 1)),
  });
}

export async function prepareChatImage(
  file: File,
  onProgress?: (ratio: number) => void,
): Promise<PreparedImage> {
  if (file.size <= IMAGE_COMPRESSION_THRESHOLD_BYTES) {
    return { file, compressed: false, originalSize: file.size };
  }

  onProgress?.(0);
  const compressed = await compressImageLocally(file, onProgress);

  if (compressed.size >= file.size) {
    onProgress?.(1);
    return { file, compressed: false, originalSize: file.size };
  }

  const result = new File([compressed], file.name, {
    type: compressed.type || file.type || 'image/jpeg',
    lastModified: file.lastModified,
  });
  onProgress?.(1);
  return { file: result, compressed: true, originalSize: file.size };
}

export async function createVideoCompressionSession(file: File): Promise<VideoCompressionSession | null> {
  if (file.size <= VIDEO_COMPRESSION_THRESHOLD_BYTES) return null;

  const {
    ALL_FORMATS,
    BlobSource,
    Conversion,
    Input,
    Mp4OutputFormat,
    Output,
    Quality,
    StreamTarget,
  } = await import('mediabunny');

  const input = new Input({ formats: ALL_FORMATS, source: new BlobSource(file) });
  let sink: ((position: number, chunk: Uint8Array) => Promise<void>) | undefined;
  let maxWrittenEnd = 0;
  const writable = new WritableStream<StreamTargetChunk>({
    write: (chunk) => {
      if (!sink) throw new Error('视频压缩输出尚未连接。');
      const end = chunk.position + chunk.data.byteLength;
      if (!Number.isSafeInteger(end)) throw new Error('压缩视频尺寸超出浏览器安全范围。');
      maxWrittenEnd = Math.max(maxWrittenEnd, end);
      return sink(chunk.position, chunk.data);
    },
  });
  const output = new Output({
    // 普通 MP4 的兼容性显著好于 fMP4；StreamTarget 保留位置写语义，Mediabunny 可在 finalize 时回写 mdat 头，媒体数据仍可边编码边发送。
    // Plain MP4 is far more compatible than fMP4; StreamTarget keeps positional writes, so
    // Mediabunny rewrites the mdat header at finalize while media still streams out.
    format: new Mp4OutputFormat({ fastStart: false }),
    target: new StreamTarget(writable, { chunked: true, chunkSize: 1024 * 1024 }),
  });

  let conversion;
  try {
    conversion = await Conversion.init({
      input,
      output,
      tracks: 'primary',
      video: async (track) => {
        const [displayHeight, frameRate] = await Promise.all([
          track.getDisplayHeight(),
          track.computeFrameRateMetrics({ targetPacketCount: 64 }),
        ]);
        return {
          codec: 'avc',
          height: Math.min(720, displayHeight),
          // 只将高帧率视频限制到 30 fps，避免上采样 24/25 fps 源。 / Cap only high-fps video at 30 fps; do not upsample 24/25 fps sources.
          frameRate: Math.min(30, frameRate.bestGuessFrameRate),
          quality: new Quality('medium'),
          hardwareAcceleration: 'prefer-hardware',
          forceTranscode: true,
        };
      },
      audio: {
        codec: 'aac',
        quality: new Quality({ bitrate: 128_000 }),
        forceTranscode: true,
      },
      tags: {},
      showWarnings: false,
    });
  } catch {
    await output.cancel().catch(() => undefined);
    input.dispose();
    return null;
  }

  // 不以“压缩成功”为代价静默丢掉音轨等主媒体轨道；无法完整转换时回退原文件。
  // Never silently drop primary tracks (e.g. audio) to call compression a success;
  // fall back to the original file when conversion cannot complete.
  if (!conversion.isValid || conversion.utilizedTracks.length === 0 || conversion.discardedTracks.length > 0) {
    await conversion.cancel().catch(() => undefined);
    input.dispose();
    return null;
  }

  const baseName = file.name.replace(/\.[^.]+$/u, '') || 'video';
  return {
    mime: 'video/mp4',
    name: `${baseName}.mp4`,
    execute: async (writeAt, onProgress) => {
      sink = writeAt;
      maxWrittenEnd = 0;
      conversion.onProgress = (ratio) => onProgress?.(Math.min(Math.max(ratio, 0), 1));
      try {
        await conversion.execute();
        onProgress?.(1);
        return maxWrittenEnd;
      } finally {
        sink = undefined;
        input.dispose();
      }
    },
  };
}
