/**
 * 临时高强度加密私聊（端到端）：
 * - 创建者生成随机房间，把 #chat=<room.psk> 链接交给对方；PSK 留在 URL hash，房间 ID 仅用于中继配对
 * - 双方 X25519 协商会话密钥，所有消息 XChaCha20-Poly1305 加密后经中继转发
 * - 消息仅存内存，刷新 / 关闭 / 断开即焚；中继全程只见密文
 *
 * Ephemeral high-strength E2E chat: the creator mints a random room and shares a #chat=<room.psk>
 * link; the PSK stays in the URL hash, the room ID only pairs at the relay. Keys are agreed via
 * X25519 and messages are XChaCha20-Poly1305 encrypted through the relay; messages live in memory
 * only and burn on refresh/close/disconnect — the relay sees ciphertext only.
 */
import {
  ArrowRight,
  Check,
  CheckCheck,
  Copy,
  Download,
  Link2,
  Loader2,
  LockKeyhole,
  LogOut,
  MessageSquareLock,
  Paperclip,
  RefreshCw,
  Send,
  ShieldCheck,
  Smile,
  Sparkles,
  Users,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import EmojiPicker from './EmojiPicker';
import ImageLightbox from './ImageLightbox';
import SafetyBadge from './SafetyBadge';
import {
  MEDIA_CHUNK_BYTES,
  createInsecureSession,
  createSession,
  destroySession,
  establishSession,
  helloMac,
  openFrame,
  peerPublicKeyFromText,
  publicKeyText,
  roomCodeOf,
  sealFrame,
  verifyHelloMac,
  type ChatSession,
  type WirePayload,
} from './chat';
import {
  IMAGE_COMPRESSION_THRESHOLD_BYTES,
  VIDEO_COMPRESSION_THRESHOLD_BYTES,
  createVideoCompressionSession,
  prepareChatImage,
} from './chatMedia';

type Phase = 'lobby' | 'waiting' | 'secure' | 'closed';
type LinkState = 'connecting' | 'waiting-peer' | 'secure' | 'peer-left' | 'disconnected' | 'full' | 'error';

interface ChatMessage {
  id: string;
  mine: boolean;
  at: number;
  kind: 'text' | 'image' | 'video' | 'system';
  text?: string;
  mediaUrl?: string;
  mediaMime?: string;
  mediaName?: string;
  mediaSize?: number;
  mediaOriginalSize?: number;
  mediaCompressed?: boolean;
  /** 我方发送链序号（已读回执匹配用） / Our tx chain seq (matched against read receipts) */
  seq?: number;
  read?: boolean;
  entrance?: 'send';
}

interface SendFxState {
  id: string;
  text: string;
  cipherA: string;
  cipherB: string;
}

type MotionMode = 'pointer' | 'sensor' | 'prompt' | 'denied' | 'none';

interface IncomingMediaTransfer {
  media: 'image' | 'video';
  mime: string;
  name: string;
  originalSize: number;
  compressed: boolean;
  buffer: SparseMediaBuffer;
  layout: 'legacy-sequential' | 'positioned' | null;
  legacyOffset: number;
  nextIndex: number;
}

interface MediaProgress {
  label: string;
  ratio: number;
  detail?: string;
}

interface SentMediaResult {
  seq: number;
  size: number;
  chunks: number;
  mime: string;
  name: string;
  localBlob?: Blob;
}

class ChatMediaTransportError extends Error {
  constructor(message = '媒体传输连接已中断。') {
    super(message);
    this.name = 'ChatMediaTransportError';
  }
}

const newId = () =>
  crypto.randomUUID?.() ?? `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;

const formatBytes = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
};

const clockOf = (at: number) =>
  new Date(at).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });

const wsUrl = () =>
  `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/ws/chat`;

const inviteLink = (session: ChatSession) => `${location.origin}/crypto/#chat=${roomCodeOf(session)}`;

/** 完整码 <room>.<psk> 或降级码 <room> / Full code <room>.<psk> or degraded <room> */
const CODE_RE = /^[A-Za-z0-9_-]{16,64}(\.[A-Za-z0-9_-]{20,64})?$/;
const WS_BUFFER_HIGH_WATER_BYTES = 4 * 1024 * 1024;
const MEDIA_SEND_BYTES_PER_SECOND = 16 * 1024 * 1024;
const SEND_FX_MS = 240;
const SEND_BUBBLE_REVEAL_MS = 155;
const CIPHER_GLYPHS = '01A7F3C9E5B2D8#%&*+=<>?/\\[]{}▓▒░';

function scrambleText(text: string, salt: number): string {
  let index = 0;
  return Array.from(text, (char) => {
    if (/\s/u.test(char)) return char;
    const code = char.codePointAt(0) ?? 0;
    const value = (code * 31 + salt * 97 + index * 53) % CIPHER_GLYPHS.length;
    index += 1;
    return CIPHER_GLYPHS[value] ?? '0';
  }).join('');
}

const wait = (ms: number) => new Promise<void>((resolve) => window.setTimeout(resolve, ms));

interface ByteRange {
  start: number;
  end: number;
}

/**
 * 稀疏媒体缓冲：支持普通顺序文件，也支持 MP4 finalize 阶段对文件头的随机回写。
 * 数据按协议块落入固定 block，覆盖写原地生效；最终 Blob 不需要再复制一份完整 Uint8Array。
 * Sparse media buffer: handles sequential files plus random header rewrites at MP4 finalize.
 * Data lands in fixed blocks where overwrites apply in place; the final Blob needs no full copy.
 */
class SparseMediaBuffer {
  private readonly blocks = new Map<number, Uint8Array>();
  private readonly coverage: ByteRange[] = [];
  private coveredBytes = 0;
  maxEnd = 0;

  write(position: number, data: Uint8Array): void {
    const end = position + data.byteLength;
    if (!Number.isSafeInteger(position) || position < 0 || !Number.isSafeInteger(end)) {
      throw new Error('媒体文件偏移超出浏览器安全范围');
    }
    if (data.byteLength === 0) return;

    let sourceOffset = 0;
    while (sourceOffset < data.byteLength) {
      const absolute = position + sourceOffset;
      const blockIndex = Math.floor(absolute / MEDIA_CHUNK_BYTES);
      const withinBlock = absolute % MEDIA_CHUNK_BYTES;
      const take = Math.min(MEDIA_CHUNK_BYTES - withinBlock, data.byteLength - sourceOffset);
      let block = this.blocks.get(blockIndex);
      if (!block) {
        block = new Uint8Array(MEDIA_CHUNK_BYTES);
        this.blocks.set(blockIndex, block);
      }
      block.set(data.subarray(sourceOffset, sourceOffset + take), withinBlock);
      sourceOffset += take;
    }

    this.addCoverage(position, end);
    this.maxEnd = Math.max(this.maxEnd, end);
  }

  isComplete(size: number): boolean {
    if (!Number.isSafeInteger(size) || size < 0 || this.maxEnd !== size || this.coveredBytes !== size) return false;
    if (size === 0) return this.coverage.length === 0;
    return this.coverage.length === 1 && this.coverage[0].start === 0 && this.coverage[0].end === size;
  }

  toBlob(size: number, type: string): Blob {
    if (!this.isComplete(size)) throw new Error('媒体文件存在未写入区间');
    const parts: BlobPart[] = [];
    const blockCount = Math.ceil(size / MEDIA_CHUNK_BYTES);
    for (let index = 0; index < blockCount; index += 1) {
      const block = this.blocks.get(index);
      if (!block) throw new Error('媒体文件分块缺失');
      const length = Math.min(MEDIA_CHUNK_BYTES, size - index * MEDIA_CHUNK_BYTES);
      parts.push((block.buffer as ArrayBuffer).slice(0, length));
    }
    return new Blob(parts, { type });
  }

  private addCoverage(start: number, end: number): void {
    let first = 0;
    while (first < this.coverage.length && this.coverage[first].end < start) first += 1;

    let mergedStart = start;
    let mergedEnd = end;
    let overlap = 0;
    let last = first;
    while (last < this.coverage.length && this.coverage[last].start <= mergedEnd) {
      const current = this.coverage[last];
      const overlapStart = Math.max(start, current.start);
      const overlapEnd = Math.min(end, current.end);
      if (overlapEnd > overlapStart) overlap += overlapEnd - overlapStart;
      mergedStart = Math.min(mergedStart, current.start);
      mergedEnd = Math.max(mergedEnd, current.end);
      last += 1;
    }

    this.coverage.splice(first, last - first, { start: mergedStart, end: mergedEnd });
    this.coveredBytes += end - start - overlap;
  }
}

const LINK_TEXT: Record<LinkState, string> = {
  connecting: '正在连接中继…',
  'waiting-peer': '等待对方加入…',
  secure: '端到端加密已建立',
  'peer-left': '对方已离开（重进链接即可继续）',
  disconnected: '连接已断开',
  full: '房间已满（同一房间最多两人）',
  error: '连接出错',
};

export default function Chat({ initialRoom }: { initialRoom?: string }) {
  const [phase, setPhase] = useState<Phase>('lobby');
  const [linkState, setLinkState] = useState<LinkState>('connecting');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState('');
  const [joinCode, setJoinCode] = useState('');
  const [safetyBadgeSeed, setSafetyBadgeSeed] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [starting, setStarting] = useState(false);
  const [emojiOpen, setEmojiOpen] = useState(false);
  const [mediaProgress, setMediaProgress] = useState<MediaProgress | null>(null);
  const [sendFx, setSendFx] = useState<SendFxState | null>(null);
  const [motionMode, setMotionMode] = useState<MotionMode>('none');
  const [previewImage, setPreviewImage] = useState<{ url: string; name: string } | null>(null);
  const closePreviewImage = useCallback(() => setPreviewImage(null), []);

  const sessionRef = useRef<ChatSession | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const shellRef = useRef<HTMLElement>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const logStageRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const urlsRef = useRef<string[]>([]);
  const leavingRef = useRef(false);
  const reconnectTimerRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const lastResyncRef = useRef(0);
  const startingRef = useRef(false);
  const incomingMediaRef = useRef(new Map<string, IncomingMediaTransfer>());
  const tiltBubbleRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (initialRoom && phase === 'lobby') void start(initialRoom);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    logRef.current?.scrollTo({
      top: logRef.current.scrollHeight,
      behavior: reducedMotion ? 'auto' : 'smooth',
    });
  }, [messages]);

  // 动态玻璃光照：桌面端只更新悬停气泡，合成层数量保持恒定；
  // 移动端转向时以 ≤30 fps 更新光向量，气泡几何保持静态以稳定帧率。
  // Dynamic glass lighting: desktop updates only the hovered bubble (constant compositor layers);
  // mobile orientation updates the light vector at <=30 fps while bubble geometry stays static.
  useEffect(() => {
    const shell = shellRef.current;
    const log = logRef.current;
    if (!shell || !log) return;
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reducedMotion) {
      setMotionMode('none');
      return;
    }

    const finePointer = window.matchMedia('(pointer: fine)').matches;
    const orientationCtor = window.DeviceOrientationEvent as typeof DeviceOrientationEvent & {
      requestPermission?: () => Promise<'granted' | 'denied'>;
    };
    if (finePointer) setMotionMode('pointer');
    else if (typeof orientationCtor !== 'undefined') {
      setMotionMode(typeof orientationCtor.requestPermission === 'function' ? 'prompt' : 'sensor');
    } else setMotionMode('none');

    let raf = 0;
    let pendingPointer: PointerEvent | null = null;
    const clearTilt = () => {
      const bubble = tiltBubbleRef.current;
      if (!bubble) return;
      bubble.classList.remove('is-tilting');
      bubble.style.removeProperty('--bubble-tilt-x');
      bubble.style.removeProperty('--bubble-tilt-y');
      bubble.style.removeProperty('--bubble-light-x');
      bubble.style.removeProperty('--bubble-light-y');
      tiltBubbleRef.current = null;
    };
    const flushPointer = () => {
      raf = 0;
      const event = pendingPointer;
      pendingPointer = null;
      if (!event) return;
      const target = event.target instanceof Element ? event.target.closest<HTMLElement>('.chat-bubble') : null;
      if (!target) {
        clearTilt();
        return;
      }
      if (tiltBubbleRef.current && tiltBubbleRef.current !== target) clearTilt();
      tiltBubbleRef.current = target;
      const rect = target.getBoundingClientRect();
      const nx = Math.min(Math.max((event.clientX - rect.left) / Math.max(rect.width, 1), 0), 1);
      const ny = Math.min(Math.max((event.clientY - rect.top) / Math.max(rect.height, 1), 0), 1);
      target.style.setProperty('--bubble-light-x', `${(nx * 100).toFixed(1)}%`);
      target.style.setProperty('--bubble-light-y', `${(ny * 100).toFixed(1)}%`);
      target.style.setProperty('--bubble-tilt-x', `${((0.5 - ny) * 1.4).toFixed(2)}deg`);
      target.style.setProperty('--bubble-tilt-y', `${((nx - 0.5) * 1.7).toFixed(2)}deg`);
      target.classList.add('is-tilting');
    };
    const onPointerMove = (event: PointerEvent) => {
      if (!finePointer) return;
      pendingPointer = event;
      if (!raf) raf = requestAnimationFrame(flushPointer);
    };
    const onPointerLeave = () => {
      pendingPointer = null;
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
      clearTilt();
    };
    log.addEventListener('pointermove', onPointerMove, { passive: true });
    log.addEventListener('pointerleave', onPointerLeave, { passive: true });

    return () => {
      log.removeEventListener('pointermove', onPointerMove);
      log.removeEventListener('pointerleave', onPointerLeave);
      if (raf) cancelAnimationFrame(raf);
      clearTilt();
    };
  }, [phase]);

  useEffect(() => {
    if (motionMode !== 'sensor') return;
    const shell = shellRef.current;
    if (!shell) return;
    let baseGamma: number | null = null;
    let baseBeta: number | null = null;
    let targetX = 50;
    let targetY = 18;
    let currentX = targetX;
    let currentY = targetY;
    let raf = 0;
    let lastPaint = 0;

    const paint = (now: number) => {
      raf = requestAnimationFrame(paint);
      if (now - lastPaint < 33) return;
      lastPaint = now;
      currentX += (targetX - currentX) * 0.22;
      currentY += (targetY - currentY) * 0.22;
      shell.style.setProperty('--glass-light-x', `${currentX.toFixed(1)}%`);
      shell.style.setProperty('--glass-light-y', `${currentY.toFixed(1)}%`);
    };
    const onOrientation = (event: DeviceOrientationEvent) => {
      if (event.gamma === null || event.beta === null) return;
      baseGamma ??= event.gamma;
      baseBeta ??= event.beta;
      const gamma = Math.min(Math.max(event.gamma - baseGamma, -18), 18);
      const beta = Math.min(Math.max(event.beta - baseBeta, -18), 18);
      targetX = 50 + gamma * 1.35;
      targetY = 18 + beta * 1.1;
    };
    window.addEventListener('deviceorientation', onOrientation, { passive: true });
    raf = requestAnimationFrame(paint);
    return () => {
      window.removeEventListener('deviceorientation', onOrientation);
      cancelAnimationFrame(raf);
      shell.style.removeProperty('--glass-light-x');
      shell.style.removeProperty('--glass-light-y');
    };
  }, [motionMode, phase]);

  // 边缘橡皮筋：只有内层消息舞台做 3D 位移，绝不移动滚动容器本身；
  // 保留原生滚动，变换开销保持低廉。
  // Edge rubber-band: only the inner message stage moves in 3D, never the scroll container
  // itself — native scrolling is preserved and the transform stays cheap.
  useEffect(() => {
    const log = logRef.current;
    const stage = logStageRef.current;
    if (!log || !stage) return;
    let startY = 0;
    let active = false;
    const reset = () => {
      active = false;
      stage.dataset.rubber = 'release';
      stage.style.setProperty('--rubber-y', '0px');
      stage.style.setProperty('--rubber-z', '0px');
      stage.style.setProperty('--rubber-scale-y', '1');
      window.setTimeout(() => { if (stage.dataset.rubber === 'release') delete stage.dataset.rubber; }, 240);
    };
    const onStart = (event: TouchEvent) => {
      startY = event.touches[0]?.clientY ?? 0;
      active = false;
      delete stage.dataset.rubber;
    };
    const onMove = (event: TouchEvent) => {
      const y = event.touches[0]?.clientY;
      if (y === undefined) return;
      const delta = y - startY;
      const atTop = log.scrollTop <= 0.5 && delta > 0;
      const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 0.5 && delta < 0;
      if (!atTop && !atBottom) {
        if (active) reset();
        return;
      }
      active = true;
      stage.dataset.rubber = 'drag';
      const displacement = Math.sign(delta) * Math.min(Math.abs(delta) * 0.12, 18);
      const compression = 1 - Math.min(Math.abs(delta) / 9000, 0.018);
      const z = -Math.min(Math.abs(delta) * 0.08, 14);
      stage.style.setProperty('--rubber-y', `${displacement.toFixed(2)}px`);
      stage.style.setProperty('--rubber-z', `${z.toFixed(2)}px`);
      stage.style.setProperty('--rubber-scale-y', compression.toFixed(4));
    };
    log.addEventListener('touchstart', onStart, { passive: true });
    log.addEventListener('touchmove', onMove, { passive: true });
    log.addEventListener('touchend', reset, { passive: true });
    log.addEventListener('touchcancel', reset, { passive: true });
    return () => {
      log.removeEventListener('touchstart', onStart);
      log.removeEventListener('touchmove', onMove);
      log.removeEventListener('touchend', reset);
      log.removeEventListener('touchcancel', reset);
    };
  }, [phase]);

  // 移动端软键盘感知：visualViewport 实际可见高度写入 --vvh，
  // 聊天面板据此收缩，输入框始终浮在键盘上方（iOS/Android 通用）。
  // Mobile keyboard awareness: the real visualViewport height feeds --vvh so the panel shrinks
  // and the composer floats above the keyboard (works on iOS and Android).
  useEffect(() => {
    const viewport = window.visualViewport;
    if (!viewport) return;
    const apply = () => {
      document.documentElement.style.setProperty('--vvh', `${Math.round(viewport.height)}px`);
    };
    apply();
    viewport.addEventListener('resize', apply);
    viewport.addEventListener('scroll', apply);
    return () => {
      viewport.removeEventListener('resize', apply);
      viewport.removeEventListener('scroll', apply);
      document.documentElement.style.removeProperty('--vvh');
    };
  }, []);

  // 会话销毁：清零密钥、释放图片 URL、断开连接 / Teardown: zero keys, revoke media URLs, disconnect.
  useEffect(
    () => () => {
      leavingRef.current = true;
      if (reconnectTimerRef.current !== null) window.clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
      if (sessionRef.current) destroySession(sessionRef.current);
      incomingMediaRef.current.clear();
      for (const url of urlsRef.current) URL.revokeObjectURL(url);
    },
    [],
  );

  const trackUrl = (url: string) => {
    urlsRef.current.push(url);
    return url;
  };

  async function start(roomCode?: string) {
    if (startingRef.current) return;
    startingRef.current = true;
    setStarting(true);
    let session: ChatSession | null = null;
    try {
      // 含 '.' 的完整码走 PSK 混合模式；纯房间码为降级模式（仅 ECDH） / Codes with '.' use PSK mode; bare room codes are degraded (ECDH only).
      session = roomCode && !roomCode.includes('.')
        ? await createInsecureSession(roomCode)
        : await createSession(roomCode);
      sessionRef.current = session;
      setPhase('waiting');
      setMessages([]);
      setSafetyBadgeSeed(null);
      connect(session);
    } catch (error) {
      if (session) destroySession(session);
      sessionRef.current = null;
      setPhase('lobby');
      toast.error(error instanceof Error ? error.message : '无法创建加密会话');
    } finally {
      startingRef.current = false;
      setStarting(false);
    }
  }

  function connect(session: ChatSession) {
    leavingRef.current = false;
    setLinkState('connecting');
    const ws = new WebSocket(wsUrl());
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    const sendHello = async () => {
      if (ws.readyState !== WebSocket.OPEN) return;
      ws.send(JSON.stringify({ t: 'hello', pub: publicKeyText(session), mac: await helloMac(session) }));
    };

    const addSystem = (text: string) =>
      setMessages((prev) => [...prev, { id: newId(), mine: false, at: Date.now(), kind: 'system', text }]);

    ws.onopen = () => ws.send(JSON.stringify({ t: 'join', room: session.roomId }));

    let receiveQueue = Promise.resolve();
    const handleMessage = async (event: MessageEvent<string | ArrayBuffer>) => {
      if (typeof event.data === 'string') {
        let msg: { t?: string; n?: number; pub?: string; mac?: string | null };
        try {
          msg = JSON.parse(event.data);
        } catch {
          return;
        }
        if (msg.t === 'joined') {
          reconnectAttemptsRef.current = 0;
          setLinkState('waiting-peer');
          void sendHello(); // 房间可能已有等待者，立即广播公钥 / The room may already have a waiter; broadcast our key now
        } else if (msg.t === 'peer-join') {
          setLinkState('waiting-peer');
          void sendHello(); // 新同伴到来，重发公钥触发协商 / New peer arrived; resend our key to trigger negotiation
        } else if (msg.t === 'hello' && typeof msg.pub === 'string') {
          try {
            const peer = peerPublicKeyFromText(msg.pub);
            // 公钥 MAC 认证：PSK 模式下中继无法替换公钥（不知道 PSK） / Public-key MAC auth: in PSK mode the relay cannot swap keys (it has no PSK)
            if (!(await verifyHelloMac(session, peer, msg.mac ?? null))) {
              toast.error('公钥认证失败：双方链接不一致，或存在中间人');
              return;
            }
            // 对方页面被移动端浏览器后台回收后重载会更换密钥对：
            // 必须重新协商，否则双方棘轮错位、后续所有帧认证失败。
            // A peer reloaded after mobile background eviction gets a fresh key pair: renegotiate,
            // or the ratchets desync and every later frame fails authentication.
            const rekey = session.sessionKey !== null && session.peerPublicKey !== null &&
              !equalBytes(session.peerPublicKey, peer);
            if (!session.sessionKey || rekey) {
              await establishSession(session, peer);
              if (rekey) {
                incomingMediaRef.current.clear();
                // 作废旧会话的我方消息序号，避免新会话已读回执误标旧消息 / Void old tx seqs so new-session receipts cannot mislabel old messages
                setMessages((prev) => prev.map((m) => (m.mine ? { ...m, seq: undefined } : m)));
                addSystem('对方重新连接，已重新建立加密通道（视觉安全徽章已更新，请再次核验）');
              }
            }
            setSafetyBadgeSeed(session.safetyBadgeSeed);
            setLinkState('secure');
          } catch {
            toast.error('公钥无效，无法建立加密');
          }
        } else if (msg.t === 'peer-leave') {
          incomingMediaRef.current.clear();
          setLinkState('peer-left');
        }
        return;
      }

      // 二进制密文帧 / Binary ciphertext frame
      try {
        const { payload, gap } = await openFrame(session, new Uint8Array(event.data));
        if (gap > 0) addSystem(`有 ${gap} 条消息未能送达（中继未转发，无补发设计）`);
        if (payload.k === 'read') {
          // 已读回执：标亮所有序号已确认的我方消息 / Read receipt: mark our messages below upTo as read
          setMessages((prev) =>
            prev.map((m) => (m.mine && m.seq !== undefined && m.seq < payload.upTo && !m.read ? { ...m, read: true } : m)),
          );
          return;
        }

        if (payload.k === 'media-start') {
          if (!payload.mime.toLowerCase().startsWith(`${payload.media}/`)) throw new Error('媒体 MIME 与类型不匹配');
          if (incomingMediaRef.current.has(payload.id)) throw new Error('媒体传输 ID 重复');
          // 正常 UI 同时只会发送一个媒体；保留少量并发余地，同时防止恶意同伴无限创建未完成传输。
          // A normal UI sends one media at a time; keep a little headroom while capping
          // hostile transfer creation.
          if (incomingMediaRef.current.size >= 4) throw new Error('同时进行的媒体传输过多');
          incomingMediaRef.current.set(payload.id, {
            media: payload.media,
            mime: payload.mime,
            name: payload.name,
            originalSize: payload.originalSize,
            compressed: payload.compressed,
            buffer: new SparseMediaBuffer(),
            layout: null,
            legacyOffset: 0,
            nextIndex: 0,
          });
          return;
        }

        if (payload.k === 'media-chunk') {
          const transfer = incomingMediaRef.current.get(payload.id);
          if (!transfer || payload.index !== transfer.nextIndex) throw new Error('媒体分块顺序无效');
          const layout = payload.offset === undefined ? 'legacy-sequential' : 'positioned';
          if (transfer.layout !== null && transfer.layout !== layout) throw new Error('媒体分块布局不能混用');
          transfer.layout ??= layout;
          const position = payload.offset ?? transfer.legacyOffset;
          transfer.buffer.write(position, payload.d);
          if (payload.offset === undefined) transfer.legacyOffset += payload.d.byteLength;
          transfer.nextIndex += 1;
          return;
        }

        if (payload.k === 'media-cancel') {
          incomingMediaRef.current.delete(payload.id);
          return;
        }

        if (payload.k === 'media-end') {
          const transfer = incomingMediaRef.current.get(payload.id);
          if (
            !transfer ||
            transfer.nextIndex !== payload.chunks ||
            !transfer.buffer.isComplete(payload.size)
          ) {
            throw new Error('媒体传输长度校验失败');
          }
          incomingMediaRef.current.delete(payload.id);
          const blob = transfer.buffer.toBlob(payload.size, transfer.mime);
          setMessages((prev) => [
            ...prev,
            {
              id: newId(),
              mine: false,
              at: Date.now(),
              kind: transfer.media,
              mediaUrl: trackUrl(URL.createObjectURL(blob)),
              mediaMime: transfer.mime,
              mediaName: transfer.name,
              mediaSize: payload.size,
              mediaOriginalSize: transfer.originalSize,
              mediaCompressed: transfer.compressed,
            },
          ]);
          sendReadReceipt();
          return;
        }

        if (payload.k === 'text') {
          setMessages((prev) => [
            ...prev,
            { id: newId(), mine: false, at: Date.now(), kind: 'text', text: payload.t },
          ]);
        } else if (payload.k === 'image') {
          // 兼容旧版单帧图片消息。 / Legacy single-frame image message.
          const blob = new Blob([payload.d.slice().buffer as ArrayBuffer], { type: payload.mime });
          setMessages((prev) => [
            ...prev,
            {
              id: newId(),
              mine: false,
              at: Date.now(),
              kind: 'image',
              mediaUrl: trackUrl(URL.createObjectURL(blob)),
              mediaMime: payload.mime,
              mediaName: payload.name,
              mediaSize: payload.d.byteLength,
              mediaOriginalSize: payload.d.byteLength,
              mediaCompressed: false,
            },
          ]);
        }
        // 立即回执已读（对方显示双勾） / Acknowledge read immediately (the peer shows double ticks)
        sendReadReceipt();
      } catch {
        toast.error('收到无法认证的消息，已丢弃');
        // 认证失败可能意味着双方会话错位（如旧版页面未重协商）：断开触发重新握手自愈。
        // Auth failure may mean session desync (stale page without renegotiation): disconnect
        // to force a rehandshake and self-heal.
        forceRehandshake();
      }
    };

    // WebSocket 事件本身不会等待 async handler；媒体分片高频到达时必须串行推进
    // 接收棘轮与组装状态，否则多个 openFrame() 可能并发读取同一 rx.chain。
    // WS events do not await async handlers; media chunks arrive fast, so the receive ratchet
    // and assembly state must advance serially or openFrame() calls race on the same rx.chain.
    ws.onmessage = (event) => {
      receiveQueue = receiveQueue.then(() => handleMessage(event)).catch((error) => {
        console.error('chat receive queue failed', error);
      });
    };

    ws.onclose = (event) => {
      if (wsRef.current === ws) wsRef.current = null;
      if (leavingRef.current || !sessionRef.current) return;
      if (event.code === 1013) {
        // 房间满：可能是未被服务器察觉的僵尸连接占座，稍后重试 / Room full: likely an unnoticed zombie connection; retry later
        setLinkState('full');
        scheduleReconnect(8000);
      } else {
        setLinkState((prev) => (prev === 'full' ? prev : 'disconnected'));
        scheduleReconnect(2500);
      }
    };
    ws.onerror = () => setLinkState('error');
  }

  const equalBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

  /** 自动重连（退避思想：普通断线 2.5s 起，上限 6 次后停手等待手动操作）
   *  Auto-reconnect with backoff: 2.5s for normal drops, stops after 6 tries and waits for manual action */
  function scheduleReconnect(delay: number) {
    if (reconnectTimerRef.current !== null) return;
    if (reconnectAttemptsRef.current >= 6) return;
    reconnectAttemptsRef.current += 1;
    reconnectTimerRef.current = window.setTimeout(() => {
      reconnectTimerRef.current = null;
      const session = sessionRef.current;
      if (session && !leavingRef.current) connect(session);
    }, delay);
  }

  /** 会话错位自愈：主动断开，借 onclose 自动重连 -> peer-join -> 双方重发 hello 重新协商
   *  Desync self-heal: disconnect on purpose; onclose reconnects, peer-join re-triggers a hello exchange */
  function forceRehandshake() {
    if (Date.now() - lastResyncRef.current < 5000) return; // 限频，防错误帧风暴引发重连循环 / Rate-limited so error-frame storms cannot loop reconnects
    lastResyncRef.current = Date.now();
    reconnectAttemptsRef.current = 0;
    wsRef.current?.close(4000, 'resync');
  }

  // 回到前台时若连接已死（移动端后台冻结常见），立即重连 / Reconnect immediately on foreground return if the socket died.
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState !== 'visible') return;
      const ws = wsRef.current;
      if (ws && ws.readyState !== WebSocket.OPEN && sessionRef.current && !leavingRef.current) {
        reconnectAttemptsRef.current = 0;
        connect(sessionRef.current);
      }
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => document.removeEventListener('visibilitychange', onVisible);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function send(payload: WirePayload): Promise<{ ok: boolean; seq?: number }> {
    const session = sessionRef.current;
    const ws = wsRef.current;
    if (!session?.sessionKey || !ws || ws.readyState !== WebSocket.OPEN) {
      toast.error('加密连接未就绪');
      return { ok: false };
    }

    // WebSocket 没有标准 drain 事件；媒体分片发送时主动观察 bufferedAmount，
    // 把网络背压一路传回视频编码器，避免慢网络把数百 MB 数据堆进 JS 内存。
    // WebSocket has no standard drain event; watching bufferedAmount while sending media chunks
    // feeds backpressure into the encoder instead of piling hundreds of MB in JS memory.
    while (ws.bufferedAmount > WS_BUFFER_HIGH_WATER_BYTES) {
      await new Promise((resolve) => window.setTimeout(resolve, 18));
      if (ws.readyState !== WebSocket.OPEN) return { ok: false };
    }

    const { frame, seq } = await sealFrame(session, payload);
    ws.send(frame.buffer as ArrayBuffer);
    return { ok: true, seq };
  }

  async function sendRequired(payload: WirePayload): Promise<number> {
    try {
      const result = await send(payload);
      if (!result.ok || result.seq === undefined) throw new ChatMediaTransportError();
      return result.seq;
    } catch (error) {
      if (error instanceof ChatMediaTransportError) throw error;
      throw new ChatMediaTransportError(error instanceof Error ? error.message : undefined);
    }
  }

  function createMediaChunkWriter(id: string) {
    let chunks = 0;
    let maxEnd = 0;
    let nextSendAt = performance.now();

    const emit = async (position: number, data: Uint8Array) => {
      if (data.byteLength === 0) return;
      // 平滑媒体帧速率，与中继的按字节限流配合；避免在低延迟网络上一瞬间
      // 把数百个分片打进服务端，同时仍保留约 128 Mbps 的高吞吐上限。
      // Smooths the media frame rate to pair with the relay's byte throttle: no instant burst
      // of hundreds of chunks on fast networks, while keeping roughly 128 Mbps throughput.
      const now = performance.now();
      const scheduledAt = Math.max(nextSendAt, now);
      const delay = scheduledAt - now;
      nextSendAt = scheduledAt + (data.byteLength / MEDIA_SEND_BYTES_PER_SECOND) * 1000;
      if (delay > 1) await new Promise((resolve) => window.setTimeout(resolve, delay));
      await sendRequired({ k: 'media-chunk', id, index: chunks, offset: position, d: data });
      chunks += 1;
      maxEnd = Math.max(maxEnd, position + data.byteLength);
    };

    return {
      writeAt: async (position: number, input: Uint8Array) => {
        const end = position + input.byteLength;
        if (!Number.isSafeInteger(position) || position < 0 || !Number.isSafeInteger(end)) {
          throw new Error('媒体文件偏移超出浏览器安全范围');
        }
        let offset = 0;
        while (offset < input.byteLength) {
          const take = Math.min(MEDIA_CHUNK_BYTES, input.byteLength - offset);
          await emit(position + offset, input.subarray(offset, offset + take));
          offset += take;
        }
      },
      finish: async (expectedSize = maxEnd) => {
        if (expectedSize !== maxEnd) throw new Error('媒体输出尺寸与写入区间不一致');
        const seq = await sendRequired({ k: 'media-end', id, size: expectedSize, chunks });
        return { seq, size: expectedSize, chunks };
      },
    };
  }

  async function cancelMediaTransfer(id: string) {
    try {
      await sendRequired({ k: 'media-cancel', id });
    } catch {
      // 连接已断开时无需再发取消帧；接收端随会话重连清理未完成传输 / No cancel frame needed when disconnected; the receiver cleans unfinished transfers on reconnect.
    }
  }

  async function sendFileTransfer(
    file: File,
    media: 'image' | 'video',
    originalSize: number,
    compressed: boolean,
    onProgress?: (sent: number, total: number) => void,
  ): Promise<SentMediaResult> {
    const id = newId();
    const mime = file.type || (media === 'image' ? 'image/jpeg' : 'video/mp4');
    const name = file.name || (media === 'image' ? 'image' : 'video');
    await sendRequired({ k: 'media-start', id, media, mime, name, originalSize, compressed });
    const writer = createMediaChunkWriter(id);

    try {
      for (let offset = 0; offset < file.size; offset += MEDIA_CHUNK_BYTES) {
        const data = new Uint8Array(await file.slice(offset, Math.min(offset + MEDIA_CHUNK_BYTES, file.size)).arrayBuffer());
        await writer.writeAt(offset, data);
        onProgress?.(Math.min(offset + data.byteLength, file.size), file.size);
      }
      const result = await writer.finish(file.size);
      onProgress?.(file.size, file.size);
      return { ...result, mime, name };
    } catch (error) {
      await cancelMediaTransfer(id);
      throw error;
    }
  }

  async function sendCompressedVideo(file: File): Promise<SentMediaResult | null> {
    const compression = await createVideoCompressionSession(file);
    if (!compression) return null;

    const id = newId();
    await sendRequired({
      k: 'media-start',
      id,
      media: 'video',
      mime: compression.mime,
      name: compression.name,
      originalSize: file.size,
      compressed: true,
    });
    const writer = createMediaChunkWriter(id);
    const localBuffer = new SparseMediaBuffer();

    try {
      const finalSize = await compression.execute(
        async (position, data) => {
          localBuffer.write(position, data);
          await writer.writeAt(position, data);
        },
        (ratio) => setMediaProgress({
          label: '正在压缩并加密发送视频',
          ratio,
          detail: '标准 MP4 · 720p · WebCodecs',
        }),
      );
      const result = await writer.finish(finalSize);
      return {
        ...result,
        mime: compression.mime,
        name: compression.name,
        localBlob: localBuffer.toBlob(finalSize, compression.mime),
      };
    } catch (error) {
      await cancelMediaTransfer(id);
      throw error;
    }
  }

  /** 已读回执：把已按序确认收到的对端序号告知对方（acked 不含跳跃缺口，不虚报已读）
   *  Read receipt: report the in-order acked peer seq; gap skips don't advance it, so no over-reporting */
  function sendReadReceipt() {
    const session = sessionRef.current;
    if (session?.rx && session.rx.acked > 0) {
      void send({ k: 'read', upTo: session.rx.acked }).catch(() => {});
    }
  }

  async function enableDeviceMotion() {
    const orientationCtor = window.DeviceOrientationEvent as typeof DeviceOrientationEvent & {
      requestPermission?: () => Promise<'granted' | 'denied'>;
    };
    if (typeof orientationCtor?.requestPermission !== 'function') {
      setMotionMode('sensor');
      return;
    }
    try {
      const permission = await orientationCtor.requestPermission();
      if (permission === 'granted') {
        setMotionMode('sensor');
        toast.success('动态玻璃已启用');
      } else {
        setMotionMode('denied');
        toast.info('未启用陀螺仪，玻璃光泽将保持静态');
      }
    } catch {
      setMotionMode('denied');
      toast.info('浏览器未授予设备方向权限');
    }
  }

  async function sendText() {
    const text = draft.trim();
    if (!text || sending) return;
    const fxId = newId();
    setSendFx({
      id: fxId,
      text,
      cipherA: scrambleText(text, 7),
      cipherB: scrambleText(text, 19),
    });
    setDraft('');
    setSending(true);
    try {
      const revealDelay = window.matchMedia('(prefers-reduced-motion: reduce)').matches
        ? 0
        : SEND_BUBBLE_REVEAL_MS;
      const [result] = await Promise.all([
        send({ k: 'text', t: text }),
        wait(revealDelay),
      ]);
      if (result.ok) {
        setMessages((prev) => [
          ...prev,
          { id: newId(), mine: true, at: Date.now(), kind: 'text', text, seq: result.seq, entrance: 'send' },
        ]);
      } else {
        setDraft(text);
      }
    } catch (error) {
      setDraft(text);
      toast.error(error instanceof Error ? error.message : '消息发送失败');
    } finally {
      const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const elapsed = reducedMotion ? 0 : SEND_FX_MS - SEND_BUBBLE_REVEAL_MS;
      window.setTimeout(() => {
        setSendFx((current) => current?.id === fxId ? null : current);
      }, elapsed);
      setSending(false);
    }
  }

  async function sendMedia(file: File | undefined) {
    if (!file) return;
    const media = file.type.startsWith('image/') ? 'image' : file.type.startsWith('video/') ? 'video' : null;
    if (!media) return toast.error('仅支持图片或视频文件');
    setSending(true);
    try {
      if (media === 'image') {
        let prepared = { file, compressed: false, originalSize: file.size };
        if (file.size > IMAGE_COMPRESSION_THRESHOLD_BYTES) {
          setMediaProgress({ label: '正在无感优化图片', ratio: 0, detail: formatBytes(file.size) });
          try {
            prepared = await prepareChatImage(file, (ratio) => setMediaProgress({
              label: '正在无感优化图片',
              ratio,
              detail: `${formatBytes(file.size)} · 本地处理`,
            }));
          } catch {
            toast.info('当前图片格式无法压缩，已自动改为原图加密传输');
          }
        }

        const result = await sendFileTransfer(
          prepared.file,
          'image',
          prepared.originalSize,
          prepared.compressed,
          (sent, total) => setMediaProgress({
            label: '正在加密发送图片',
            ratio: total === 0 ? 1 : sent / total,
            detail: `${formatBytes(sent)} / ${formatBytes(total)}`,
          }),
        );
        setMessages((prev) => [
          ...prev,
          {
            id: newId(),
            mine: true,
            at: Date.now(),
            kind: 'image',
            mediaUrl: trackUrl(URL.createObjectURL(prepared.file)),
            mediaMime: result.mime,
            mediaName: result.name,
            mediaSize: result.size,
            mediaOriginalSize: prepared.originalSize,
            mediaCompressed: prepared.compressed,
            seq: result.seq,
          },
        ]);
        if (prepared.compressed) {
          toast.success(`图片已自动压缩 ${formatBytes(prepared.originalSize)} → ${formatBytes(result.size)}`);
        }
        return;
      }

      let result: SentMediaResult | null = null;
      if (file.size > VIDEO_COMPRESSION_THRESHOLD_BYTES) {
        setMediaProgress({ label: '正在准备视频压缩', ratio: 0, detail: formatBytes(file.size) });
        try {
          result = await sendCompressedVideo(file);
        } catch (error) {
          if (error instanceof ChatMediaTransportError) throw error;
          toast.info('当前浏览器无法完成此视频的本地转码，已自动改为原文件加密传输');
        }
      }

      if (!result) {
        result = await sendFileTransfer(file, 'video', file.size, false, (sent, total) => setMediaProgress({
          label: '正在加密发送视频',
          ratio: total === 0 ? 1 : sent / total,
          detail: `${formatBytes(sent)} / ${formatBytes(total)}`,
        }));
      }

      setMessages((prev) => [
        ...prev,
        {
          id: newId(),
          mine: true,
          at: Date.now(),
          kind: 'video',
          // 压缩路径必须预览“实际发送出去的文件”：源视频可能是 HEVC 等浏览器
          // 无法直接播放的格式，继续引用原文件会错误显示 0:00。
          // The compressed path must preview the file actually being sent: source videos may be
          // HEVC or otherwise unplayable, and keeping the original reference would show 0:00.
          mediaUrl: trackUrl(URL.createObjectURL(result.localBlob ?? file)),
          mediaMime: result.mime,
          mediaName: result.name,
          mediaSize: result.size,
          mediaOriginalSize: file.size,
          mediaCompressed: result.size < file.size,
          seq: result.seq,
        },
      ]);
      if (result.size < file.size) {
        toast.success(`视频已自动压缩 ${formatBytes(file.size)} → ${formatBytes(result.size)}`);
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '媒体发送失败');
    } finally {
      setSending(false);
      setMediaProgress(null);
      if (fileRef.current) fileRef.current.value = '';
    }
  }

  function leave() {
    leavingRef.current = true;
    if (reconnectTimerRef.current !== null) {
      window.clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    reconnectAttemptsRef.current = 0;
    wsRef.current?.close();
    wsRef.current = null;
    if (sessionRef.current) destroySession(sessionRef.current);
    sessionRef.current = null;
    incomingMediaRef.current.clear();
    for (const url of urlsRef.current) URL.revokeObjectURL(url);
    urlsRef.current = [];
    setPhase('lobby');
    setMessages([]);
    setSafetyBadgeSeed(null);
    setJoinCode('');
    setMediaProgress(null);
    setSendFx(null);
  }

  const copy = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label}已复制`);
    } catch {
      toast.error(`无法复制${label}，请检查浏览器剪贴板权限`);
    }
  };

  const session = sessionRef.current;
  const invite = session ? inviteLink(session) : '';
  const degraded = session !== null && !session.pskProtected;

  /* ---------------- Lobby 大厅 ---------------- */
  if (phase === 'lobby') {
    return (
      <>
        <section className="hero">
          <h1>临时加密私聊</h1>
          <p>端到端加密的一对一会话：消息、图片与视频仅以密文中转，聊天内容不在服务端保存。</p>
        </section>

        <section className="workspace-card chat-lobby">
          <button type="button" className="chat-create" disabled={starting} onClick={() => void start(undefined)}>
            {starting ? <Loader2 className="spin" size={26} /> : <MessageSquareLock size={26} />}
            <strong>创建私密房间</strong>
            <span>生成一次性房间码，把链接发给对方即可开始</span>
            <em className="chat-create-go"><ArrowRight size={16} /></em>
          </button>

          <div className="chat-join">
            <span className="chat-join-label"><Users size={14} /> 已有房间码？</span>
            <input
              value={joinCode}
              onChange={(event) => setJoinCode(event.target.value.trim())}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && CODE_RE.test(joinCode)) void start(joinCode);
              }}
              placeholder="粘贴完整房间码（含密钥部分更安全）"
              aria-label="完整房间码"
              spellCheck={false}
              autoComplete="off"
            />
            <button
              type="button"
              className="chat-join-btn"
              disabled={starting || !CODE_RE.test(joinCode)}
              onClick={() => void start(joinCode)}
            >
              加入
            </button>
          </div>

          <ul className="chat-trust">
            <li><ShieldCheck size={15} /> 链接内置预共享密钥：与密钥协商双因子混合，中继无法中间人</li>
            <li><MessageSquareLock size={15} /> 双向棘轮：每条消息独立密钥，用后即弃、拒绝重放</li>
            <li><LogOut size={15} /> 消息仅存内存，关闭页面立即销毁</li>
          </ul>
        </section>
      </>
    );
  }

  /* ---------------- Room 房间 ---------------- */
  const secure = linkState === 'secure';
  return (
    <section
      ref={shellRef}
      className="workspace-card chat-shell"
      data-glass-motion={motionMode}
    >
      <header className="chat-header">
        <div className="chat-header-left">
          <span className={`chat-status-dot ${secure ? 'ok' : 'warn'} ${linkState === 'connecting' ? 'pulse' : ''}`} aria-hidden="true" />
          <span className="chat-status-text" role="status" aria-live="polite">{LINK_TEXT[linkState]}</span>
          {safetyBadgeSeed && <SafetyBadge seed={safetyBadgeSeed} pskProtected={!degraded} />}
        </div>
        <div className="chat-header-right">
          {motionMode === 'prompt' && (
            <button
              type="button"
              className="chat-icon-action chat-motion-enable"
              onClick={() => void enableDeviceMotion()}
              title="启用陀螺仪动态玻璃光泽"
              aria-label="启用陀螺仪动态玻璃光泽"
            >
              <Sparkles size={15} />
            </button>
          )}
          <button type="button" className="chat-icon-action" onClick={() => void copy(invite, '邀请链接')} title="复制邀请链接" aria-label="复制邀请链接">
            <Link2 size={15} />
          </button>
          <button type="button" className="chat-icon-action danger" onClick={leave} title="销毁会话并离开" aria-label="销毁会话并离开">
            <LogOut size={15} />
          </button>
        </div>
      </header>

      {degraded && (
        <div className="chat-notice danger">
          <ShieldCheck size={16} />
          <span>降级模式（仅密钥协商，无预共享密钥）：请通过<b>聊天以外</b>的渠道核验双方视觉安全徽章，否则无法排除中间人。</span>
        </div>
      )}

      {linkState === 'waiting-peer' || linkState === 'connecting' ? (
        <div className="chat-invite-panel">
          <Loader2 className="spin" size={20} />
          <div>
            <strong>等待对方加入</strong>
            <p>把一次性链接发给对方。PSK 仅保留在链接 hash 中；中继只接收随机房间 ID：</p>
          </div>
          <div className="chat-invite-link">
            <code>{invite}</code>
            <button type="button" onClick={() => void copy(invite, '邀请链接')}>
              <Copy size={14} /> 复制
            </button>
          </div>
        </div>
      ) : linkState === 'full' ? (
        <div className="chat-notice danger"><Users size={16} /> 该房间已有两人，无法再加入。</div>
      ) : linkState === 'disconnected' || linkState === 'error' ? (
        <div className="chat-notice">
          <RefreshCw size={16} />
          <span>与中继的连接已断开，消息不会被补发（临时会话设计）。</span>
          <button type="button" onClick={() => sessionRef.current && connect(sessionRef.current)}>重新连接</button>
        </div>
      ) : null}

      <div className="chat-log" ref={logRef} aria-live="polite" aria-label="加密聊天消息">
        <div className="chat-log-stage" ref={logStageRef}>
          {messages.length === 0 && secure && (
            <div className="chat-empty">已建立加密通道。点击顶部视觉安全徽章，与对方核验一致后再交流敏感内容。</div>
          )}
          {messages.map((message, index) => {
            if (message.kind === 'system') {
              return (
                <div key={message.id} className="chat-row system">
                  <div className="chat-system">{message.text}</div>
                </div>
              );
            }
            const prev = messages[index - 1];
            const next = messages[index + 1];
            const groupStart = !prev || prev.kind === 'system' || prev.mine !== message.mine;
            const groupEnd = !next || next.kind === 'system' || next.mine !== message.mine;
            const liquidJoin = !groupStart && prev?.kind !== 'system';
            return (
              <div
                key={message.id}
                className={`chat-row ${message.mine ? 'mine' : ''} ${groupStart ? 'group-start' : 'group-inner'} ${groupEnd ? 'group-end' : ''} ${liquidJoin ? 'liquid-join' : ''} ${message.entrance === 'send' ? 'send-impact' : ''}`}
              >
                <div className={`chat-bubble ${message.kind === 'image' || message.kind === 'video' ? 'media' : ''}`}>
                  {liquidJoin && <span className="chat-liquid-bridge" aria-hidden="true" />}
                {message.kind === 'text' ? (
                  <p>{message.text}</p>
                ) : message.kind === 'image' ? (
                  <div className="chat-media-card">
                    <button
                      type="button"
                      className="chat-image"
                      onClick={() => message.mediaUrl && setPreviewImage({ url: message.mediaUrl, name: message.mediaName ?? '图片消息' })}
                      title={`${message.mediaName ?? '图片'} · 点击查看`}
                      aria-haspopup="dialog"
                    >
                      <img src={message.mediaUrl} alt={message.mediaName ?? '图片消息'} />
                    </button>
                    <div className="chat-media-info">
                      <span title={message.mediaName}>{message.mediaName || '图片'}</span>
                      <div className="chat-media-actions">
                        <em>
                          {message.mediaCompressed && message.mediaOriginalSize !== undefined
                            ? `${formatBytes(message.mediaOriginalSize)} → ${formatBytes(message.mediaSize ?? 0)}`
                            : formatBytes(message.mediaSize ?? 0)}
                        </em>
                        {message.mediaUrl && (
                          <a
                            className="chat-media-download"
                            href={message.mediaUrl}
                            download={message.mediaName || 'image'}
                            title="下载图片"
                            aria-label={`下载 ${message.mediaName || '图片'}`}
                          >
                            <Download size={14} />
                          </a>
                        )}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="chat-media-card">
                    <video
                      className="chat-video"
                      src={message.mediaUrl}
                      controls
                      playsInline
                      preload="metadata"
                    />
                    <div className="chat-media-info">
                      <span title={message.mediaName}>{message.mediaName || '视频'}</span>
                      <div className="chat-media-actions">
                        <em>
                          {message.mediaCompressed && message.mediaOriginalSize !== undefined
                            ? `${formatBytes(message.mediaOriginalSize)} → ${formatBytes(message.mediaSize ?? 0)}`
                            : formatBytes(message.mediaSize ?? 0)}
                        </em>
                        {message.mediaUrl && (
                          <a
                            className="chat-media-download"
                            href={message.mediaUrl}
                            download={message.mediaName || 'video.mp4'}
                            title="下载视频"
                            aria-label={`下载 ${message.mediaName || '视频'}`}
                          >
                            <Download size={14} />
                          </a>
                        )}
                      </div>
                    </div>
                  </div>
                )}
                <span className="chat-meta">
                  {clockOf(message.at)}
                  {message.mine && (
                    <span className="chat-ticks" title={message.read ? '已读' : '已送达'}>
                      {message.read ? <CheckCheck size={13} strokeWidth={2.6} /> : <Check size={13} strokeWidth={2.6} />}
                    </span>
                  )}
                </span>
              </div>
              </div>
            );
          })}
        </div>
      </div>

      {mediaProgress && (
        <div
          className="chat-transfer-progress"
          role="progressbar"
          aria-label={mediaProgress.label}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(mediaProgress.ratio * 100)}
        >
          <div className="chat-transfer-progress-copy">
            <span><Loader2 className="spin" size={13} /> {mediaProgress.label}</span>
            <em>{mediaProgress.detail ?? `${Math.round(mediaProgress.ratio * 100)}%`}</em>
          </div>
          <div className="chat-transfer-progress-track">
            <span style={{ transform: `scaleX(${Math.min(Math.max(mediaProgress.ratio, 0), 1)})` }} />
          </div>
        </div>
      )}

      <div className="chat-composer">
        <button
          type="button"
          className="chat-icon-action"
          disabled={!secure || sending}
          onClick={() => fileRef.current?.click()}
          title="发送图片或视频（大文件自动压缩）"
          aria-label="发送图片或视频"
        >
          <Paperclip size={18} />
        </button>
        <input
          ref={fileRef}
          type="file"
          accept="image/*,video/*"
          hidden
          onChange={(event) => void sendMedia(event.target.files?.[0])}
        />
        <div className="chat-input-wrap">
          {emojiOpen && (
            <EmojiPicker
              onPick={(emoji) => setDraft((value) => value + emoji)}
              onClose={() => setEmojiOpen(false)}
            />
          )}
          {sendFx && (
            <div className="chat-send-fx" key={sendFx.id} aria-hidden="true">
              <div className="chat-send-cipher">
                <span>{sendFx.cipherA}</span>
                <span>{sendFx.cipherB}</span>
              </div>
              <div className="chat-send-lock">
                <LockKeyhole size={15} />
                {Array.from({ length: 6 }, (_, index) => <i key={index} />)}
              </div>
              <div className="chat-send-projectile">
                <span>{sendFx.text}</span>
              </div>
            </div>
          )}
          <textarea
            value={draft}
            rows={1}
            placeholder={secure ? '输入消息，Enter 发送…' : '等待加密通道建立…'}
            aria-label="聊天消息"
            disabled={!secure || sending}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
                event.preventDefault();
                void sendText();
              }
            }}
          />
          <button
            type="button"
            className={`chat-emoji-btn ${emojiOpen ? 'active' : ''}`}
            disabled={!secure}
            onClick={() => setEmojiOpen((value) => !value)}
            aria-label="表情"
            title="表情"
          >
            <Smile size={19} />
          </button>
        </div>
        <button
          type="button"
          className="chat-send"
          disabled={!secure || !draft.trim() || sending}
          onClick={() => void sendText()}
          aria-label="发送消息"
        >
          {sending ? <Loader2 className="spin" size={16} /> : <Send size={16} />}
        </button>
      </div>

      <div className="chat-ephemeral-note">
        <Check size={12} /> 临时会话：刷新或关闭页面即销毁全部消息与密钥
        <span className="chat-build-fp" title="当前加密模块构建指纹（供审计核对，改动即变）">
          fp {String(import.meta.env.__CHAT_FP__ ?? 'dev')}
        </span>
      </div>
      {previewImage && (
        <ImageLightbox
          url={previewImage.url}
          name={previewImage.name}
          onClose={closePreviewImage}
        />
      )}
    </section>
  );
}
