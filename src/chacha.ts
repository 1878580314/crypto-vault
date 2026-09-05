import { loadSodium } from './sodium.ts';

/**
 * ChaCha20-Poly1305（IETF）唯一后端：libsodium WASM。
 * 私聊与密钥分发模块本来就硬依赖 libsodium，双后端回退只会带来
 * 额外的依赖与选择分支；WASM 不可用的环境这三个功能都无法工作。
 * Single backend: libsodium's WebAssembly IETF ChaCha20-Poly1305.
 * Chat and key distribution hard-require libsodium anyway, so a JS fallback
 * only added a dependency and a branch without saving any real environment.
 */
export interface ChaChaCipher {
  encrypt(plaintext: Uint8Array, nonce: Uint8Array, aad: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, nonce: Uint8Array, aad: Uint8Array): Uint8Array;
}

export async function createChaChaCipher(key: Uint8Array): Promise<ChaChaCipher> {
  if (key.byteLength !== 32) throw new Error('ChaCha20-Poly1305 需要 256 位密钥。');
  const sodium = await loadSodium();
  return {
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
