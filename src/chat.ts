/**
 * 加密私聊协议层 v3（纯函数，无 UI / 无网络；KDF / MAC 全部采用 BLAKE3）。
 * Encrypted chat protocol v3: pure functions, no UI or network; BLAKE3 for all KDF/MAC.
 *
 * 威胁模型：中继服务器完全不可信（可见并可篡改 / 重放 / 替换一切帧）。
 * Threat model: the relay is fully untrusted (sees and may tamper/replay/replace any frame).
 *
 * - 房间：22 字符 Base64URL 随机 ID +（可选）43 字符 PSK，只存于分享链接 hash，永不发送给中继；
 *   Room: Base64URL random ID + optional PSK live only in the share-link hash, never sent to the relay.
 * - 密钥协商（双因子混合）：master = BLAKE3keyed(roomKey, X25519(shared) ‖ PSK?)，任一因子保密即安全；
 *   仅 ECDH 时中继可 MITM（降级模式，UI 显著警告）；仅 PSK 泄露时仍缺 ECDH 因子，中继无法解密；
 *   PSK 模式下 hello 携带 BLAKE3keyed(PSK, 公钥) MAC，
 *   中继替换公钥即 MAC 失败 —— MITM 在协议层死亡。
 *   Agreement: master = BLAKE3keyed(roomKey, X25519(shared) ‖ PSK?) — either factor staying secret suffices;
 *   ECDH-only is MITM-able (degraded mode, UI warning); a leaked PSK alone still lacks ECDH;
 *   with PSK the hello public-key MAC kills MITM.
 * - 消息棘轮：双向独立 KDF 链，msgKey(n) 单向派生、用后即弃；每帧序号严格递增且 AAD 绑定：
 *   重放 / 回退严格拒绝，丢帧跳跃对齐不中断会话；对方页面重载换新密钥对后凭认证新 hello 重协商。
 *   Ratchet: two independent KDF chains, per-message keys one-way and used once; frame seq is
 *   strictly increasing and AAD-bound — replays/rewinds rejected, gaps skipped with alignment;
 *   peers renegotiate via authenticated fresh hello after a reload.
 * - AEAD：XChaCha20-Poly1305，随机 192 位 nonce。 / AEAD: XChaCha20-Poly1305 with random 192-bit nonces.
 * - 临时性：密钥材料仅存内存，destroySession 逐字节清零。
 *   Ephemeral: key material lives in memory only and is byte-wise zeroed by destroySession.
 */
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { decode, encode } from '@msgpack/msgpack';
import { base64UrlToBytes, bytesToBase64Url } from './crypto.ts';
import { loadSodium } from './sodium.ts';

const ROOM_BYTES = 16;
const PSK_BYTES = 32;
const NONCE_BYTES = 24;
const KEY_BYTES = 32;
const MAC_BYTES = 16;
const SEQ_BYTES = 4;
/**
 * 单帧最多跨过 1024 条；超出即拒绝，限制恶意序号的棘轮派生，并为重连缓存留余量。
 * Largest gap a frame may skip; larger seqs are rejected to bound ratchet derivation
 * from malicious input. 1024 leaves headroom for reconnect message caches.
 */
export const MAX_SEQ_GAP = 1024;
/**
 * 旧版单帧图片载荷的上限（媒体分片协议之外的遗留兼容通道）。
 * Legacy single-frame image payload cap; the chunked media protocol supersedes it.
 */
export const MAX_IMAGE_BYTES = 4 * 1024 * 1024;
/**
 * 单帧密文上限：合法帧最大为旧版 4 MiB 图片帧，8 MiB 已留足信封余量；
 * 更大的帧在 AEAD 之前直接拒绝，挡住中继推送的超大恶意帧（避免先解密再失败的 CPU 开销）。
 * Frame size ceiling: the largest legitimate frame is a legacy 4 MiB image, so 8 MiB leaves
 * ample envelope headroom; bigger frames are rejected before AEAD to deny the relay a
 * free decrypt-then-fail CPU burn.
 */
export const MAX_FRAME_BYTES = 8 * 1024 * 1024;

const enc = (text: string) => new TextEncoder().encode(text);

/** BLAKE3 derive_key（KDF 模式）：context 即域分离标签 / Native KDF mode; the context string is the domain label */
const kdf = (context: string, material: Uint8Array, dkLen: number): Uint8Array =>
  blake3(material, { context: enc(context), dkLen });

/** 线路明文（加密前的载荷） / Wire plaintext (payload before encryption) */
export type WirePayload =
  | { k: 'text'; t: string }
  | { k: 'image'; mime: string; name: string; d: Uint8Array }
  | {
      k: 'media-start';
      id: string;
      media: 'image' | 'video';
      mime: string;
      name: string;
      originalSize: number;
      compressed: boolean;
    }
  | { k: 'media-chunk'; id: string; index: number; offset?: number; d: Uint8Array }
  | { k: 'media-end'; id: string; size: number; chunks: number }
  | { k: 'media-cancel'; id: string }
  /** 已读回执：已确认收到对方发送链的第 upTo 条（不含） / Read receipt: peer's tx chain confirmed up to (exclusive) */
  | { k: 'read'; upTo: number }
  /** 徽章核验确认：fp 为确认方所见徽章指纹前缀，与当前会话绑定 / Badge confirmation; fp binds it to the current session fingerprint */
  | { k: 'verify'; fp: string };

export const MEDIA_CHUNK_BYTES = 256 * 1024;

export interface Ratchet {
  chain: Uint8Array;
  nextSeq: number;
  /** 连续按序接收的最高序号 + 1（已读回执基准；跳过丢失帧时不推进，不虚报已读）
   *  Highest in-order seq + 1: read-receipt basis; not advanced across gaps, never over-reports reads */
  acked: number;
}

export interface ChatSession {
  roomId: string;
  /** 预共享密钥（来自链接；降级模式为 null） / Pre-shared key from the link; null in degraded mode */
  psk: Uint8Array | null;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  peerPublicKey: Uint8Array | null;
  /** 双方由本次 master 独立派生的视觉安全徽章种子（32 字节，小写 64 位 hex）
   *  Safety-badge seed derived from this master by both sides (32 bytes, lowercase 64-char hex) */
  safetyBadgeSeed: string | null;
  pskProtected: boolean;
  /** 发送链与接收链（建立后生成） / Tx and rx ratchets (created once the session is established) */
  tx: Ratchet | null;
  rx: Ratchet | null;
}

/** 房间码 / 公钥统一使用 crypto.ts 的 Base64URL 实现（与 sodium URLSAFE_NO_PADDING 输出逐字节一致）
 *  Room codes / public keys share crypto.ts's Base64URL helpers (byte-identical to sodium URLSAFE_NO_PADDING) */
const b64 = (bytes: Uint8Array) => bytesToBase64Url(bytes);
const unb64 = (text: string) => base64UrlToBytes(text);

/** 解析房间码：<room> 或 <room>.<psk> / Parse a room code: <room> or <room>.<psk> */
export function parseRoomCode(code: string): { room: string; psk: Uint8Array | null } {
  const dot = code.indexOf('.');
  if (dot === -1) return { room: code, psk: null };
  return { room: code.slice(0, dot), psk: unb64(code.slice(dot + 1)) };
}

export function roomCodeOf(session: { roomId: string; psk: Uint8Array | null }): string {
  return session.psk ? `${session.roomId}.${b64(session.psk)}` : session.roomId;
}

export async function createSession(roomCode?: string): Promise<ChatSession> {
  const s = await loadSodium();
  const parsed = roomCode ? parseRoomCode(roomCode) : { room: null, psk: null as Uint8Array | null };
  // 裸房间码（无 PSK 部分）属于显式降级模式：这里若静默补随机 PSK，对方按原链接加入会握手失败。
  // A bare room code means an explicitly degraded session; silently minting a random PSK here
  // would desync the peer that joins with the original link.
  if (roomCode !== undefined && parsed.psk === null) {
    throw new Error('房间码缺少预共享密钥；无密钥会话请显式使用降级入口。');
  }
  if (parsed.psk && parsed.psk.length !== PSK_BYTES) throw new Error('预共享密钥长度无效');
  const room = parsed.room ?? b64(s.randombytes_buf(ROOM_BYTES));
  const psk = parsed.psk ?? s.randombytes_buf(PSK_BYTES); // 默认创建即带 PSK / New sessions include a PSK by default
  const pair = s.crypto_box_keypair();
  return {
    roomId: room,
    psk,
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    peerPublicKey: null,
    safetyBadgeSeed: null,
    pskProtected: true,
    tx: null,
    rx: null,
  };
}

/** 显式创建降级会话（无 PSK，仅 ECDH）——UI 须显著警告 / Explicitly create a degraded session (no PSK, ECDH only); the UI must warn prominently */
export async function createInsecureSession(roomId: string): Promise<ChatSession> {
  const s = await loadSodium();
  const pair = s.crypto_box_keypair();
  return {
    roomId,
    psk: null,
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    peerPublicKey: null,
    safetyBadgeSeed: null,
    pskProtected: false,
    tx: null,
    rx: null,
  };
}

export function publicKeyText(session: ChatSession): string {
  return b64(session.publicKey);
}

export function peerPublicKeyFromText(text: string): Uint8Array {
  return unb64(text);
}

/** hello 帧的公钥 MAC（仅 PSK 模式）：BLAKE3 keyed，PSK 即 MAC 密钥
 *  Hello-frame public-key MAC (PSK mode only): BLAKE3 keyed mode with the PSK as the MAC key */
export async function helloMac(session: ChatSession): Promise<string | null> {
  if (!session.psk) return null;
  return b64(blake3(session.publicKey, { key: session.psk, dkLen: MAC_BYTES }));
}

/** 校验对方 hello 的公钥 MAC；失败说明公钥被替换或 PSK 不符 / Verify the peer hello MAC; failure means a replaced key or PSK mismatch */
export async function verifyHelloMac(session: ChatSession, peerPublicKey: Uint8Array, mac: string | null): Promise<boolean> {
  if (!session.psk) return mac === null || mac === undefined ? true : false;
  if (typeof mac !== 'string') return false;
  const expected = b64(blake3(peerPublicKey, { key: session.psk, dkLen: MAC_BYTES }));
  return expected === mac;
}

/** 收到对方公钥（已通过 MAC 认证）后建立会话 / Establish the session once the peer key is MAC-authenticated */
export async function establishSession(session: ChatSession, peerPublicKey: Uint8Array): Promise<void> {
  const s = await loadSodium();
  // 公钥字典序决定双方向链的归属：小者发送用链 1，大者发送用链 2；
  // 先拒绝自协商，避免为失败路径派生并暂存 master。
  // Lexicographic key order assigns chain directions: the smaller key sends on chain 1,
  // the larger on chain 2. Self-negotiation is rejected first so no master is derived for a doomed path.
  const cmp = compareBytes(session.publicKey, peerPublicKey);
  if (cmp === 0) throw new Error('不能与自己协商');

  const shared = s.crypto_scalarmult(session.privateKey, peerPublicKey);
  const psk = session.psk;
  const roomKey = kdf('crypta-chat:v3:room', enc(session.roomId), KEY_BYTES);

  const masterInput = new Uint8Array(shared.length + (psk ? psk.length : 0));
  masterInput.set(shared);
  if (psk) masterInput.set(psk, shared.length);
  let master: Uint8Array;
  try {
    master = blake3(masterInput, { key: roomKey, dkLen: KEY_BYTES });
  } finally {
    // ECDH / KDF 输入仅在建立 master 时需要，避免重协商后残留 / Only needed for master creation; no residue across renegotiations.
    shared.fill(0);
    masterInput.fill(0);
    roomKey.fill(0);
  }

  try {
    const chain1 = kdf('crypta-chat:v3:chain-1', master, KEY_BYTES);
    const chain2 = kdf('crypta-chat:v3:chain-2', master, KEY_BYTES);
    const safetyBadgeBytes = kdf('crypta-chat:v3:safety-badge', master, KEY_BYTES);
    let safetyBadgeSeed: string;
    try {
      safetyBadgeSeed = bytesToHex(safetyBadgeBytes);
    } finally {
      safetyBadgeBytes.fill(0);
    }

    // 这是重协商入口：新状态提交前清除旧会话的可复用材料 / Renegotiation entry: purge old reusable material before committing the new state.
    session.tx?.chain.fill(0);
    session.rx?.chain.fill(0);
    session.tx = { chain: cmp < 0 ? chain1 : chain2, nextSeq: 0, acked: 0 };
    session.rx = { chain: cmp < 0 ? chain2 : chain1, nextSeq: 0, acked: 0 };
    session.safetyBadgeSeed = safetyBadgeSeed;
    session.peerPublicKey = peerPublicKey;
  } finally {
    // master 仅用于派生双方向链与徽章种子，提交后立即清零、不驻留会话。
    // master only seeds the chains and badge; zero it on commit rather than retaining it.
    master.fill(0);
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

/** 从棘轮链取第 n 条消息密钥并推进状态 / Derive the next message key from the chain and advance it */
function messageKey(chain: Uint8Array): Uint8Array {
  return kdf('crypta-chat:v3:msg', chain, KEY_BYTES);
}

function advance(chain: Uint8Array): Uint8Array {
  return kdf('crypta-chat:v3:next', chain, KEY_BYTES);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** 解码并验证线路载荷结构，避免无效明文也提交接收棘轮状态。 / Decode and validate wire payload structure; invalid plaintexts must not commit rx state. */
function decodeWirePayload(plaintext: Uint8Array): WirePayload {
  const value: unknown = decode(plaintext);
  if (!isRecord(value) || typeof value.k !== 'string') throw new Error('载荷结构无效');

  switch (value.k) {
    case 'text':
      if (typeof value.t !== 'string') throw new Error('文本载荷结构无效');
      return { k: 'text', t: value.t };
    case 'image':
      if (
        typeof value.mime !== 'string' ||
        typeof value.name !== 'string' ||
        !(value.d instanceof Uint8Array)
      ) {
        throw new Error('图片载荷结构无效');
      }
      return { k: 'image', mime: value.mime, name: value.name, d: value.d };
    case 'media-start':
      if (
        typeof value.id !== 'string' || value.id.length < 1 || value.id.length > 96 ||
        (value.media !== 'image' && value.media !== 'video') ||
        typeof value.mime !== 'string' || value.mime.length < 1 || value.mime.length > 255 ||
        typeof value.name !== 'string' || value.name.length > 1024 ||
        typeof value.originalSize !== 'number' || !Number.isSafeInteger(value.originalSize) || value.originalSize < 0 ||
        typeof value.compressed !== 'boolean'
      ) {
        throw new Error('媒体起始载荷结构无效');
      }
      return {
        k: 'media-start',
        id: value.id,
        media: value.media,
        mime: value.mime,
        name: value.name,
        originalSize: value.originalSize,
        compressed: value.compressed,
      };
    case 'media-chunk':
      if (
        typeof value.id !== 'string' || value.id.length < 1 || value.id.length > 96 ||
        typeof value.index !== 'number' || !Number.isSafeInteger(value.index) || value.index < 0 ||
        (value.offset !== undefined && (
          typeof value.offset !== 'number' ||
          !Number.isSafeInteger(value.offset) ||
          value.offset < 0
        )) ||
        !(value.d instanceof Uint8Array) || value.d.byteLength > MEDIA_CHUNK_BYTES
      ) {
        throw new Error('媒体分块载荷结构无效');
      }
      if (
        value.offset !== undefined &&
        !Number.isSafeInteger(value.offset + value.d.byteLength)
      ) {
        throw new Error('媒体分块偏移超出安全范围');
      }
      return {
        k: 'media-chunk',
        id: value.id,
        index: value.index,
        ...(value.offset === undefined ? {} : { offset: value.offset }),
        d: value.d,
      };
    case 'media-end':
      if (
        typeof value.id !== 'string' || value.id.length < 1 || value.id.length > 96 ||
        typeof value.size !== 'number' || !Number.isSafeInteger(value.size) || value.size < 0 ||
        typeof value.chunks !== 'number' || !Number.isSafeInteger(value.chunks) || value.chunks < 0
      ) {
        throw new Error('媒体结束载荷结构无效');
      }
      return { k: 'media-end', id: value.id, size: value.size, chunks: value.chunks };
    case 'media-cancel':
      if (typeof value.id !== 'string' || value.id.length < 1 || value.id.length > 96) {
        throw new Error('媒体取消载荷结构无效');
      }
      return { k: 'media-cancel', id: value.id };
    case 'read':
      if (typeof value.upTo !== 'number' || !Number.isSafeInteger(value.upTo) || value.upTo < 0) {
        throw new Error('已读回执载荷结构无效');
      }
      return { k: 'read', upTo: value.upTo };
    case 'verify':
      if (typeof value.fp !== 'string' || value.fp.length < 1 || value.fp.length > 128) {
        throw new Error('徽章核验载荷结构无效');
      }
      return { k: 'verify', fp: value.fp };
    default:
      throw new Error('载荷类型无效');
  }
}

/**
 * 加密一帧：[seq:u32be][nonce:24][ciphertext]；消息密钥取发送链第 seq 步，用后即弃；
 * AAD 绑定 协议版本 : 房间 : 方向 : 序号 —— 重放/跨房/跨方向全部失败。
 * Encrypt one frame: [seq:u32be][nonce:24][ciphertext]; the message key is tx chain step seq, single-use.
 * AAD binds version : room : direction : seq — replays, cross-room and cross-direction frames all fail.
 */
export async function sealFrame(
  session: ChatSession,
  payload: WirePayload
): Promise<{ frame: Uint8Array; seq: number }> {
  const s = await loadSodium();
  if (!session.tx) throw new Error('会话密钥尚未建立');

  // 载荷超过单帧上限时先拒绝再推进棘轮：发出方不应为必然被拒的帧消耗序号。
  // Reject oversized payloads before advancing the ratchet: the sender must not burn
  // a sequence number on a frame the peer is guaranteed to refuse.
  const plaintext = encode(payload) as Uint8Array;
  if (plaintext.byteLength + SEQ_BYTES + NONCE_BYTES + 16 > MAX_FRAME_BYTES) {
    throw new Error('载荷超出单帧大小上限');
  }

  const seq = session.tx.nextSeq;
  const previousChain = session.tx.chain;
  const msgKey = messageKey(previousChain);
  session.tx.chain = advance(previousChain);
  previousChain.fill(0);
  session.tx.nextSeq = seq + 1;

  const nonce = s.randombytes_buf(NONCE_BYTES);
  const seqBytes = new Uint8Array(SEQ_BYTES);
  new DataView(seqBytes.buffer).setUint32(0, seq, false);

  // 发送链编号：己方公钥较小者用 1，较大者用 2；接收方按对方链编号校验。
  // Tx chain number: 1 if our key is smaller, else 2; the receiver checks against the peer's number.
  const dir = compareBytes(session.publicKey, session.peerPublicKey!) < 0 ? '1' : '2';
  const aad = enc(`crypta-chat:v3:${session.roomId}:${dir}:${seq}`);

  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    msgKey,
  );
  msgKey.fill(0);

  const frame = new Uint8Array(SEQ_BYTES + NONCE_BYTES + ciphertext.length);
  frame.set(seqBytes);
  frame.set(nonce, SEQ_BYTES);
  frame.set(ciphertext, SEQ_BYTES + NONCE_BYTES);
  return { frame, seq };
}

/**
 * 解密并认证一帧；重放（seq 落后）严格拒绝，丢失帧允许跳过并对齐棘轮。
 * 返回 { payload, gap }：gap > 0 表示跳过了 gap 条未送达的帧（调用方应提示）。
 * Decrypt and authenticate one frame: replays are strictly rejected, gaps may be skipped to
 * re-align the ratchet. Returns { payload, gap } where gap > 0 means that many lost frames (notify user).
 */
export async function openFrame(
  session: ChatSession,
  frame: Uint8Array,
): Promise<{ payload: WirePayload; gap: number }> {
  const s = await loadSodium();
  const rx = session.rx;
  if (!rx) throw new Error('会话密钥尚未建立');
  if (frame.byteLength < SEQ_BYTES + NONCE_BYTES + 16) throw new Error('帧长度无效');
  if (frame.byteLength > MAX_FRAME_BYTES) throw new Error('帧长度超出协议上限');

  const seq = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(0, false);
  if (seq < rx.nextSeq) throw new Error('重放帧已拒绝');

  // 中继不补发：丢失的帧允许跳过（对齐棘轮后继续），缺口由调用方提示用户。
  // 向后（重放/乱序回退）仍然严格拒绝；已读回执以 acked 为准，跳帧不虚报已读。
  // The relay never re-sends: lost frames may be skipped (the ratchet re-aligns, delivery
  // continues) and the caller reports gaps. Rewinds/replays stay strictly rejected; acks follow acked only.
  const expected = rx.nextSeq;
  const gap = seq - expected;
  if (gap > MAX_SEQ_GAP) {
    throw new Error(`序号跳跃过大：最多允许跳过 ${MAX_SEQ_GAP} 条消息`);
  }

  const dir = compareBytes(session.publicKey, session.peerPublicKey!) < 0 ? '2' : '1';
  const aad = enc(`crypta-chat:v3:${session.roomId}:${dir}:${seq}`);
  const nonce = frame.subarray(SEQ_BYTES, SEQ_BYTES + NONCE_BYTES);
  const ciphertext = frame.subarray(SEQ_BYTES + NONCE_BYTES);

  // 在副本上试算整条路径；认证与载荷结构验证成功前绝不提交 rx 状态。
  // Trial-run the whole path on a copy; commit rx state only after auth and structure validation pass.
  let candidateChain: Uint8Array = rx.chain.slice();
  for (let skipped = 0; skipped < gap; skipped += 1) {
    const previousChain = candidateChain;
    candidateChain = advance(previousChain);
    previousChain.fill(0);
  }
  const msgKey = messageKey(candidateChain);
  let nextChain: Uint8Array | null = null;

  try {
    const plaintext = s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, msgKey);
    const payload = decodeWirePayload(plaintext);
    nextChain = advance(candidateChain);
    const previousChain = rx.chain;
    rx.chain = nextChain;
    previousChain.fill(0);
    rx.nextSeq = seq + 1;
    if (gap === 0) rx.acked = seq + 1;
    return { payload, gap };
  } finally {
    msgKey.fill(0);
    candidateChain.fill(0);
    // 认证/结构校验失败时 nextChain 尚未提交，不能留下派生出的密钥材料。
    // If auth/structure checks failed, nextChain was never committed: zero the derived material.
    if (nextChain && rx.chain !== nextChain) nextChain.fill(0);
  }
}

/** 销毁会话材料（逐字节清零，含棘轮链） / Destroy session material (byte-wise zeroing, ratchet chains included) */
export function destroySession(session: ChatSession): void {
  session.tx?.chain.fill(0);
  session.rx?.chain.fill(0);
  session.privateKey.fill(0);
  session.psk?.fill(0);
  session.tx = null;
  session.rx = null;
  session.peerPublicKey = null;
  session.safetyBadgeSeed = null;
  session.psk = null;
}
