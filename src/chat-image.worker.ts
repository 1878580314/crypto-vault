import imageCompression from 'browser-image-compression';

const IMAGE_TARGET_MB = 2;

self.onmessage = (event: MessageEvent<File>) => {
  const file = event.data;
  void imageCompression(file, {
    maxSizeMB: IMAGE_TARGET_MB,
    maxWidthOrHeight: 2560,
    initialQuality: 0.86,
    alwaysKeepResolution: false,
    preserveExif: false,
    // 已在本项目打包的 worker 内运行；启用库自带 worker 会嵌套 worker 并请求其 CDN libURL。
    // Already running inside our own bundled worker; enabling the library worker
    // would create a nested worker and use its CDN libURL.
    useWebWorker: false,
    onProgress: (progress) => self.postMessage({ type: 'progress', progress }),
  }).then(
    (result) => self.postMessage({ type: 'done', file: result }),
    (error: unknown) => self.postMessage({
      type: 'error',
      message: error instanceof Error ? error.message : '图片压缩失败。',
    }),
  );
};
