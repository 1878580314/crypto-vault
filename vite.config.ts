import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

/** 加密聊天模块的构建指纹：源码任何改动都会改变此值（防代码投毒的审计锚点） */
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
      // 开发环境：评论/聊天 API 与 WS 中继走本地服务
      '/api': {
        target: 'http://127.0.0.1:8787',
        ws: true,
      },
    },
  },
  build: {
    target: 'es2022',
    sourcemap: false,
  },
});
