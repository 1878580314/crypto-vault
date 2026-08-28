import { decode, encode } from '@msgpack/msgpack';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  createPassphraseKdf,
  derivePassphraseKey,
  parseKeyDerivationInfo,
  type KeyDerivationInfo,
} from './crypto';

const PUBLIC_PREFIX = 'crypta:pub:v1:';
const PRIVATE_PREFIX = 'crypta:priv:v1:';
const IDENTITY_PREFIX = 'crypta:identity:v1:';
const PACKAGE_PREFIX = 'crypta:key:v1:';
const IDENTITY_AAD = new TextEncoder().encode('CRYPTA-IDENTITY-V1');

interface KeyPackageEnvelope {
  magic: 'CRYPTAKEY';
  version: 1;
  recipientFingerprint: string;
  sealedKey: Uint8Array;
  createdAt: string;
}

interface ProtectedIdentityEnvelope {
  magic: 'CRYPTAIDENTITY';
  version: 1;
  keyDerivation: KeyDerivationInfo;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export interface RecipientIdentity {
  publicKey: string;
  privateKey: string;
  fingerprint: string;
}

let sodiumPromise: Promise<typeof import('libsodium-wrappers')['default']> | undefined;

async function sodium() {
  sodiumPromise ??= import('libsodium-wrappers').then(async (module) => {
    const instance = module.default;
    await instance.ready;
    return instance;
  });
  return sodiumPromise;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error('密钥文本编码无效。');
  }
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  if (bytes.buffer instanceof ArrayBuffer && bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes.buffer;
  }
  return bytes.slice().buffer;
}

function parsePrefixedBytes(value: string, prefix: string, label: string, expectedLength: number): Uint8Array {
  const trimmed = value.trim();
  if (!trimmed.startsWith(prefix)) throw new Error(`${label}格式无效。`);
  const bytes = fromBase64Url(trimmed.slice(prefix.length));
  if (bytes.byteLength !== expectedLength) throw new Error(`${label}长度无效。`);
  return bytes;
}

export function recipientFingerprint(publicKey: Uint8Array): string {
  const digest = sha256(publicKey);
  return Array.from(digest.subarray(0, 16), (byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .match(/.{1,4}/gu)!
    .join('-')
    .toUpperCase();
}

export async function generateRecipientIdentity(): Promise<RecipientIdentity> {
  const box = await sodium();
  const pair = box.crypto_box_keypair('uint8array');
  return {
    publicKey: PUBLIC_PREFIX + toBase64Url(pair.publicKey),
    privateKey: PRIVATE_PREFIX + toBase64Url(pair.privateKey),
    fingerprint: recipientFingerprint(pair.publicKey),
  };
}

export async function protectRecipientIdentity(privateKeyText: string, passphrase: string): Promise<string> {
  if (!passphrase) throw new Error('请为身份私钥设置备份口令。');
  const privateKey = parsePrefixedBytes(privateKeyText, PRIVATE_PREFIX, '接收者私钥', 32);
  const kdf = createPassphraseKdf();
  let wrappingKey: Uint8Array | undefined;
  try {
    wrappingKey = await derivePassphraseKey(passphrase, kdf);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      bytesToArrayBuffer(wrappingKey),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt'],
    );
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: bytesToArrayBuffer(nonce),
        additionalData: bytesToArrayBuffer(IDENTITY_AAD),
        tagLength: 128,
      },
      cryptoKey,
      bytesToArrayBuffer(privateKey),
    ));
    const envelope: ProtectedIdentityEnvelope = {
      magic: 'CRYPTAIDENTITY',
      version: 1,
      keyDerivation: kdf,
      nonce,
      ciphertext,
    };
    return IDENTITY_PREFIX + toBase64Url(encode(envelope));
  } finally {
    wrappingKey?.fill(0);
    privateKey.fill(0);
  }
}

async function unlockRecipientPrivateKey(identityText: string, passphrase?: string): Promise<Uint8Array> {
  const trimmed = identityText.trim();
  if (trimmed.startsWith(PRIVATE_PREFIX)) {
    return parsePrefixedBytes(trimmed, PRIVATE_PREFIX, '接收者私钥', 32);
  }
  if (!trimmed.startsWith(IDENTITY_PREFIX)) throw new Error('接收身份格式无效。');
  if (!passphrase) throw new Error('该身份文件受口令保护，请输入备份口令。');
  const encoded = fromBase64Url(trimmed.slice(IDENTITY_PREFIX.length));
  let decoded: unknown;
  try {
    decoded = decode(encoded);
  } catch {
    throw new Error('无法解析加密身份文件。');
  }
  if (!decoded || typeof decoded !== 'object') throw new Error('加密身份文件无效。');
  const envelope = decoded as Record<string, unknown>;
  if (envelope.magic !== 'CRYPTAIDENTITY' || envelope.version !== 1) throw new Error('不支持该身份文件版本。');
  const kdf = parseKeyDerivationInfo(envelope.keyDerivation);
  if (kdf.type !== 'argon2id') throw new Error('身份文件 KDF 无效。');
  if (!(envelope.nonce instanceof Uint8Array) || envelope.nonce.byteLength !== 12) throw new Error('身份文件 nonce 无效。');
  if (!(envelope.ciphertext instanceof Uint8Array) || envelope.ciphertext.byteLength !== 48) throw new Error('身份文件密文无效。');
  let wrappingKey: Uint8Array | undefined;
  try {
    wrappingKey = await derivePassphraseKey(passphrase, kdf);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      bytesToArrayBuffer(wrappingKey),
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    let privateKey: Uint8Array;
    try {
      privateKey = new Uint8Array(await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: bytesToArrayBuffer(envelope.nonce),
          additionalData: bytesToArrayBuffer(IDENTITY_AAD),
          tagLength: 128,
        },
        cryptoKey,
        bytesToArrayBuffer(envelope.ciphertext),
      ));
    } catch {
      throw new Error('身份备份口令错误，或身份文件已损坏。');
    }
    if (privateKey.byteLength !== 32) throw new Error('身份私钥长度无效。');
    return privateKey;
  } finally {
    wrappingKey?.fill(0);
  }
}

export function inspectRecipientPublicKey(value: string): { bytes: Uint8Array; fingerprint: string } {
  const bytes = parsePrefixedBytes(value, PUBLIC_PREFIX, '接收者公钥', 32);
  return { bytes, fingerprint: recipientFingerprint(bytes) };
}

export async function sealRawKeyForRecipient(rawKey: Uint8Array, publicKeyText: string): Promise<{
  packageText: string;
  recipientFingerprint: string;
}> {
  if (rawKey.byteLength !== 32) throw new Error('只能封装 256 位原始密钥。');
  const recipient = inspectRecipientPublicKey(publicKeyText);
  const box = await sodium();
  const sealedKey = box.crypto_box_seal(rawKey, recipient.bytes, 'uint8array');
  const envelope: KeyPackageEnvelope = {
    magic: 'CRYPTAKEY',
    version: 1,
    recipientFingerprint: recipient.fingerprint,
    sealedKey,
    createdAt: new Date().toISOString(),
  };
  return {
    packageText: PACKAGE_PREFIX + toBase64Url(encode(envelope)),
    recipientFingerprint: recipient.fingerprint,
  };
}

export async function openSealedRawKey(packageText: string, identityText: string, identityPassphrase?: string): Promise<{
  rawKey: Uint8Array;
  recipientFingerprint: string;
}> {
  const privateKey = await unlockRecipientPrivateKey(identityText, identityPassphrase);
  const trimmed = packageText.trim();
  if (!trimmed.startsWith(PACKAGE_PREFIX)) throw new Error('CRYPTA KEY 密钥包格式无效。');
  const payload = fromBase64Url(trimmed.slice(PACKAGE_PREFIX.length));
  let decoded: unknown;
  try {
    decoded = decode(payload);
  } catch {
    throw new Error('无法解析 CRYPTA KEY 密钥包。');
  }
  if (!decoded || typeof decoded !== 'object') throw new Error('CRYPTA KEY 密钥包无效。');
  const envelope = decoded as Record<string, unknown>;
  if (envelope.magic !== 'CRYPTAKEY' || envelope.version !== 1) throw new Error('不支持该密钥包版本。');
  if (typeof envelope.recipientFingerprint !== 'string' || !(envelope.sealedKey instanceof Uint8Array)) {
    throw new Error('CRYPTA KEY 密钥包字段无效。');
  }

  const box = await sodium();
  try {
    const publicKey = box.crypto_scalarmult_base(privateKey, 'uint8array');
    const fingerprint = recipientFingerprint(publicKey);
    if (fingerprint !== envelope.recipientFingerprint) {
      throw new Error('该密钥包不是为这把私钥生成的。');
    }
    let rawKey: Uint8Array;
    try {
      rawKey = box.crypto_box_seal_open(envelope.sealedKey, publicKey, privateKey, 'uint8array');
    } catch {
      throw new Error('无法打开密钥包：私钥不匹配，或密钥包已损坏。');
    }
    if (rawKey.byteLength !== 32) throw new Error('密钥包内容长度无效。');
    return { rawKey, recipientFingerprint: fingerprint };
  } finally {
    privateKey.fill(0);
  }
}

