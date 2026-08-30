/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** 加密聊天模块构建指纹（vite.config.ts 注入） / Chat module build fingerprint (injected by vite.config.ts) */
  readonly __CHAT_FP__?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
