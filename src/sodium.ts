/**
 * libsodium 的唯一加载入口：主线程与各 Worker 共享同一个动态导入点，
 * 避免“静态 + 动态”两种引用方式把同一 WASM 库打进两个 chunk。
 * The single entry point for libsodium: main thread and workers share one
 * dynamic import site so the same WASM library is never bundled twice.
 */
type Sodium = typeof import('libsodium-wrappers')['default'];

let sodiumPromise: Promise<Sodium> | undefined;

export function loadSodium(): Promise<Sodium> {
  sodiumPromise ??= import('libsodium-wrappers').then(async (module) => {
    const sodium = module.default;
    await sodium.ready;
    return sodium;
  });
  return sodiumPromise;
}
