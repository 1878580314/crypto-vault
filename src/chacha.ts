import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

type SodiumModule = typeof import('libsodium-wrappers');
type Sodium = SodiumModule['default'];

export type ChaChaBackend = 'libsodium-wasm' | 'noble-js';

export interface ChaChaCipher {
  backend: ChaChaBackend;
  encrypt(plaintext: Uint8Array, nonce: Uint8Array, aad: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, nonce: Uint8Array, aad: Uint8Array): Uint8Array;
}

let sodiumPromise: Promise<Sodium | null> | undefined;

async function loadSodium(): Promise<Sodium | null> {
  sodiumPromise ??= import('libsodium-wrappers')
    .then(async (module) => {
      const sodium = module.default;
      await sodium.ready;
      return sodium;
    })
    .catch(() => null);
  return sodiumPromise;
}

/**
 * 优先使用 libsodium 的 WASM IETF ChaCha20-Poly1305 实现；WASM 无法初始化时回退到小型、经审计的 noble JS 实现。
 * Prefer libsodium's WebAssembly IETF ChaCha20-Poly1305 implementation. Noble stays as a small,
 * audited fallback for environments where WASM cannot initialize.
 */
export async function createChaChaCipher(key: Uint8Array): Promise<ChaChaCipher> {
  if (key.byteLength !== 32) throw new Error('ChaCha20-Poly1305 需要 256 位密钥。');
  const sodium = await loadSodium();
  if (sodium) {
    return {
      backend: 'libsodium-wasm',
      encrypt: (plaintext, nonce, aad) => sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
        plaintext,
        aad,
        null,
        nonce,
        key,
        'uint8array',
      ),
      decrypt: (ciphertext, nonce, aad) => sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        aad,
        nonce,
        key,
        'uint8array',
      ),
    };
  }

  return {
    backend: 'noble-js',
    encrypt: (plaintext, nonce, aad) => chacha20poly1305(key, nonce, aad).encrypt(plaintext),
    decrypt: (ciphertext, nonce, aad) => chacha20poly1305(key, nonce, aad).decrypt(ciphertext),
  };
}

