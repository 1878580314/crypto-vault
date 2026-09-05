import { decode, encode } from '@msgpack/msgpack';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { createChaChaCipher } from './chacha.ts';

export type AlgorithmId = 'AES-256-GCM' | 'CHACHA20-POLY1305';
export type ContentKind = 'text' | 'file';

export interface PayloadMeta {
  algorithm: AlgorithmId;
  kind: ContentKind;
  name?: string;
  mime?: string;
  size: number;
  createdAt: string;
}

interface Envelope {
  magic: 'CRYPTA';
  version: 1;
  header: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

interface PublicHeader {
  algorithm: AlgorithmId;
  keyDerivation?: KeyDerivationInfo;
}

export interface RawKeyDerivation {
  type: 'raw';
}

export interface Argon2idKeyDerivation {
  type: 'argon2id';
  salt: Uint8Array;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

export type KeyDerivationInfo = RawKeyDerivation | Argon2idKeyDerivation;

interface ProtectedPayload {
  kind: ContentKind;
  name?: string;
  mime?: string;
  size: number;
  createdAt: string;
  data: Uint8Array;
}

export interface DecryptedPayload {
  data: Uint8Array;
  meta: PayloadMeta;
}

export const KEY_BYTES = 32;
export const NONCE_BYTES = 12;
export const TEXT_PREFIX = 'crypta:v1:';
export const ARGON2_MEMORY_KIB = 64 * 1024;
export const ARGON2_ITERATIONS = 3;
export const ARGON2_PARALLELISM = 4;
export const ARGON2_SALT_BYTES = 16;

const encoder = new TextEncoder();

export function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  if (
    bytes.buffer instanceof ArrayBuffer &&
    bytes.byteOffset === 0 &&
    bytes.byteLength === bytes.buffer.byteLength
  ) {
    return bytes.buffer;
  }
  return bytes.slice().buffer;
}

function toUint8Array(value: unknown, field: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  throw new Error(`密文容器中的 ${field} 字段无效。`);
}

export function parseKeyDerivationInfo(value: unknown): KeyDerivationInfo {
  if (value === undefined) return { type: 'raw' };
  if (!value || typeof value !== 'object') throw new Error('密文密钥派生信息无效。');
  const kdf = value as Record<string, unknown>;
  if (kdf.type === 'raw') return { type: 'raw' };
  if (kdf.type !== 'argon2id') throw new Error('密文使用了不受支持的密钥派生算法。');
  if (!(kdf.salt instanceof Uint8Array) || kdf.salt.length !== ARGON2_SALT_BYTES) {
    throw new Error('Argon2id 盐值无效。');
  }
  if (
    kdf.memoryKiB !== ARGON2_MEMORY_KIB ||
    kdf.iterations !== ARGON2_ITERATIONS ||
    kdf.parallelism !== ARGON2_PARALLELISM
  ) {
    throw new Error('该密文使用了当前版本不接受的 Argon2id 参数。');
  }
  return {
    type: 'argon2id',
    salt: kdf.salt,
    memoryKiB: ARGON2_MEMORY_KIB,
    iterations: ARGON2_ITERATIONS,
    parallelism: ARGON2_PARALLELISM,
  };
}

function parsePublicHeader(header: Uint8Array): PublicHeader {
  const value = decode(header) as Partial<PublicHeader> | null;
  if (!value || typeof value !== 'object') throw new Error('密文头部无效。');
  if (value.algorithm !== 'AES-256-GCM' && value.algorithm !== 'CHACHA20-POLY1305') {
    throw new Error('密文使用了不受支持的算法。');
  }
  return { algorithm: value.algorithm, keyDerivation: parseKeyDerivationInfo(value.keyDerivation) };
}

function parseProtectedPayload(input: Uint8Array): ProtectedPayload {
  let value: Partial<ProtectedPayload> | null;
  try {
    value = decode(input) as Partial<ProtectedPayload> | null;
  } catch {
    throw new Error('解密后的内容结构无效。');
  }
  if (!value || typeof value !== 'object') throw new Error('解密后的内容结构无效。');
  if (value.kind !== 'text' && value.kind !== 'file') throw new Error('密文内容类型无效。');
  if (typeof value.size !== 'number' || !Number.isSafeInteger(value.size) || value.size < 0) {
    throw new Error('密文长度元数据无效。');
  }
  if (typeof value.createdAt !== 'string') throw new Error('密文时间元数据无效。');
  if (value.name !== undefined && typeof value.name !== 'string') throw new Error('密文文件名无效。');
  if (value.mime !== undefined && typeof value.mime !== 'string') throw new Error('密文 MIME 类型无效。');
  if (!(value.data instanceof Uint8Array)) throw new Error('密文数据字段无效。');
  return value as ProtectedPayload;
}

function parseEnvelope(input: Uint8Array): Envelope {
  let decoded: unknown;
  try {
    decoded = decode(input);
  } catch {
    throw new Error('无法解析密文，文件可能已损坏或格式不正确。');
  }

  if (!decoded || typeof decoded !== 'object') throw new Error('密文容器无效。');
  const value = decoded as Record<string, unknown>;
  if (value.magic !== 'CRYPTA' || value.version !== 1) {
    throw new Error('无法识别该密文格式或版本。');
  }

  return {
    magic: 'CRYPTA',
    version: 1,
    header: toUint8Array(value.header, 'header'),
    nonce: toUint8Array(value.nonce, 'nonce'),
    ciphertext: toUint8Array(value.ciphertext, 'ciphertext'),
  };
}

async function aesEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    bytesToArrayBuffer(key),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const result = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: bytesToArrayBuffer(nonce),
      additionalData: bytesToArrayBuffer(aad),
      tagLength: 128,
    },
    cryptoKey,
    bytesToArrayBuffer(plaintext),
  );
  return new Uint8Array(result);
}

async function aesDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    bytesToArrayBuffer(key),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  const result = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: bytesToArrayBuffer(nonce),
      additionalData: bytesToArrayBuffer(aad),
      tagLength: 128,
    },
    cryptoKey,
    bytesToArrayBuffer(ciphertext),
  );
  return new Uint8Array(result);
}

async function encryptRaw(
  algorithm: AlgorithmId,
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (algorithm === 'AES-256-GCM') return aesEncrypt(plaintext, key, nonce, aad);
  return (await createChaChaCipher(key)).encrypt(plaintext, nonce, aad);
}

async function decryptRaw(
  algorithm: AlgorithmId,
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (algorithm === 'AES-256-GCM') return aesDecrypt(ciphertext, key, nonce, aad);
  return (await createChaChaCipher(key)).decrypt(ciphertext, nonce, aad);
}

export function generateKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

export function createNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
}

export function createPassphraseKdf(): Argon2idKeyDerivation {
  return {
    type: 'argon2id',
    salt: crypto.getRandomValues(new Uint8Array(ARGON2_SALT_BYTES)),
    memoryKiB: ARGON2_MEMORY_KIB,
    iterations: ARGON2_ITERATIONS,
    parallelism: ARGON2_PARALLELISM,
  };
}

export async function derivePassphraseKey(
  passphrase: string,
  kdf: Argon2idKeyDerivation,
  onProgress?: (progress: number) => void,
): Promise<Uint8Array> {
  if (passphrase.length === 0) throw new Error('文本口令不能为空。');
  const validated = parseKeyDerivationInfo(kdf);
  if (validated.type !== 'argon2id') throw new Error('Argon2id 参数无效。');
  return argon2idAsync(utf8ToBytes(passphrase), validated.salt, {
    t: validated.iterations,
    m: validated.memoryKiB,
    p: validated.parallelism,
    dkLen: KEY_BYTES,
    version: 0x13,
    maxmem: 96 * 1024 * 1024,
    asyncTick: 8,
    onProgress,
  });
}

export function bytesToBase64Url(data: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < data.length; offset += chunkSize) {
    binary += String.fromCharCode(...data.subarray(offset, offset + chunkSize));
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

export function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.trim().replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    throw new Error('Base64/Base64URL 编码无效。');
  }
}

export function parseKey(value: string): Uint8Array {
  const input = value.trim();
  if (!input) throw new Error('请输入 256 位密钥。');

  let key: Uint8Array;
  if (/^[0-9a-fA-F]{64}$/u.test(input)) {
    key = Uint8Array.from(input.match(/.{2}/gu) ?? [], (byte) => Number.parseInt(byte, 16));
  } else {
    key = base64UrlToBytes(input);
  }

  if (key.length !== KEY_BYTES) {
    throw new Error(`密钥必须恰好为 ${KEY_BYTES} 字节（256 位）。`);
  }
  return key;
}

export async function keyFingerprint(key: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytesToArrayBuffer(key)));
  return Array.from(digest.subarray(0, 6), (byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .match(/.{1,4}/gu)
    ?.join(' · ') ?? '';
}

export async function encryptPayload(
  data: Uint8Array,
  key: Uint8Array,
  meta: Omit<PayloadMeta, 'size' | 'createdAt'>,
  keyDerivation: KeyDerivationInfo = { type: 'raw' },
): Promise<Uint8Array> {
  if (key.length !== KEY_BYTES) throw new Error('无效的 256 位密钥。');
  const fullMeta: PayloadMeta = {
    ...meta,
    size: data.byteLength,
    createdAt: new Date().toISOString(),
  };
  const header = encode({ algorithm: fullMeta.algorithm, keyDerivation } satisfies PublicHeader);
  const payload: ProtectedPayload = {
    kind: fullMeta.kind,
    size: fullMeta.size,
    createdAt: fullMeta.createdAt,
    data,
    ...(fullMeta.name !== undefined ? { name: fullMeta.name } : {}),
    ...(fullMeta.mime !== undefined ? { mime: fullMeta.mime } : {}),
  };
  const protectedPayload = encode(payload);
  const nonce = createNonce();
  const ciphertext = await encryptRaw(fullMeta.algorithm, protectedPayload, key, nonce, header);
  return encode({
    magic: 'CRYPTA',
    version: 1,
    header,
    nonce,
    ciphertext,
  } satisfies Envelope);
}

export function inspectPayloadHeader(input: Uint8Array): PublicHeader {
  const envelope = parseEnvelope(input);
  return parsePublicHeader(envelope.header);
}

export async function decryptPayload(input: Uint8Array, key: Uint8Array): Promise<DecryptedPayload> {
  if (key.length !== KEY_BYTES) throw new Error('无效的 256 位密钥。');
  const envelope = parseEnvelope(input);
  const publicHeader = parsePublicHeader(envelope.header);
  if (envelope.nonce.length !== NONCE_BYTES) throw new Error('密文 nonce 长度无效。');

  let plaintext: Uint8Array;
  try {
    plaintext = await decryptRaw(publicHeader.algorithm, envelope.ciphertext, key, envelope.nonce, envelope.header);
  } catch {
    throw new Error('解密失败：密钥错误，或密文/元数据已被修改。');
  }
  const protectedPayload = parseProtectedPayload(plaintext);
  if (protectedPayload.data.byteLength !== protectedPayload.size) {
    throw new Error('解密后的数据长度与加密元数据不一致。');
  }
  const meta: PayloadMeta = {
    algorithm: publicHeader.algorithm,
    kind: protectedPayload.kind,
    name: protectedPayload.name,
    mime: protectedPayload.mime,
    size: protectedPayload.size,
    createdAt: protectedPayload.createdAt,
  };
  return { data: protectedPayload.data, meta };
}

export function textToPackageBytes(value: string): Uint8Array {
  const text = value.trim();
  if (!text) throw new Error('请输入待解密的密文。');
  const payload = text.startsWith(TEXT_PREFIX) ? text.slice(TEXT_PREFIX.length) : text;
  return base64UrlToBytes(payload);
}

export function packageBytesToText(value: Uint8Array): string {
  return `${TEXT_PREFIX}${bytesToBase64Url(value)}`;
}

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

export function decodeUtf8(value: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(value);
  } catch {
    throw new Error('解密成功，但内容不是有效的 UTF-8 文本。');
  }
}
