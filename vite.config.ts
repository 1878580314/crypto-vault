import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

/** 加密聊天模块的构建指纹：源码任何改动都会改变此值（防代码投毒的审计锚点）
 *  Chat module build fingerprint: changes on any source edit (audit anchor against code poisoning) */
function chatFingerprint(): string {
  const files = [
    'src/chat.ts',
    'src/chatMedia.ts',
    'src/chat-image.worker.ts',
    'src/Chat.tsx',
    'src/App.tsx',
  ];
  const hash = createHash('sha256');
  for (const file of files) hash.update(readFileSync(file));
  return hash.digest('hex').slice(0, 16);
}

export default defineConfig({
  base: '/crypto/',
  plugins: [react()],
  worker: {
    format: 'es',
  },
  define: {
    'import.meta.env.__CHAT_FP__': JSON.stringify(chatFingerprint()),
  },
  server: {
    proxy: {
      // 开发环境：评论/聊天 API 与 WS 中继走本地服务 / Dev: comment/chat API and WS relay via local server
      '/api': {
        target: 'http://127.0.0.1:8787',
        ws: true,
      },
    },
  },
  build: {
    target: 'es2022',
    sourcemap: false,
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            // 固定命名主线程的 libsodium chunk，便于识别与缓存核对。
            // 注意：Worker 构建是独立的打包图（worker.rolldownOptions），其内嵌副本
            // 目前无法与主线程共享同一文件，属打包器架构限制。
            // Give the main-thread libsodium chunk a stable name for identification and
            // cache auditing. The worker build is a separate bundling graph
            // (worker.rolldownOptions) whose embedded copy cannot be merged with this
            // one — a bundler architecture limitation.
            { name: 'libsodium', test: /libsodium/ },
          ],
        },
      },
    },
  },
});
