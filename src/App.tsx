import {
  ArrowLeft,
  ArrowRight,
  Binary,
  Check,
  Clipboard,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileArchive,
  FileCheck2,
  FileKey2,
  FileText,
  FileUp,
  Fingerprint,
  GitFork,
  KeyRound,
  Loader2,
  LockKeyhole,
  MessageSquareLock,
  RefreshCw,
  ShieldCheck,
  Moon,
  Sun,
  UnlockKeyhole,
  X,
  Zap,
} from 'lucide-react';
import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { Toaster, toast } from 'sonner';
import KeyExchange from './KeyExchange';
import {
  decodeUtf8,
  createPassphraseKdf,
  decryptPayload,
  derivePassphraseKey,
  encryptPayload,
  generateKey,
  inspectPayloadHeader,
  keyFingerprint,
  bytesToBase64Url,
  packageBytesToText,
  parseKey,
  textToPackageBytes,
  utf8,
  type AlgorithmId,
  type KeyDerivationInfo,
  type PayloadMeta,
} from './crypto';
import {
  STREAM_CHUNK_BYTES,
  STREAM_THRESHOLD_BYTES,
  SavePickerCancelledError,
  StreamUserCancelledError,
  decryptFileStreaming,
  encryptFileStreaming,
  inspectStreamingFile,
  supportsStreamingFileSave,
  usesSystemFilePickerForStreaming,
  type StreamProgress,
} from './stream';

// 懒加载加密私聊：连带 libsodium WASM、msgpack 与表情面板一起移出首屏，移动端首包显著瘦身；
// 点击「加密私聊」或携带 #chat 链接进入时才拉取。
// Lazy-load the encrypted chat: moves libsodium WASM, msgpack and the emoji panel out of the
// first screen (slimmer mobile payload); fetched only on click or via a #chat link.
const loadChat = () => import('./Chat');
const Chat = lazy(loadChat);

// 非首屏工具按需加载。完整性模块包含八种哈希实现；从默认加密页拆出后，
// 访问者只下载当前真正使用的能力。
// Non-first-screen tools load on demand. The integrity module bundles eight hash
// implementations; splitting it out means visitors download only what they use.
const loadIntegrityChecker = () => import('./IntegrityChecker');
const IntegrityChecker = lazy(loadIntegrityChecker);

type Operation = 'encrypt' | 'decrypt';
type InputMode = 'text' | 'file';
type KeyMode = 'raw' | 'passphrase';
type FileFormat = 'checking' | 'legacy' | 'stream';
type ToolMode = 'vault' | 'integrity' | 'chat';
type ThemeMode = 'dark' | 'light';

interface FileResult {
  blob?: Blob;
  name: string;
  meta: PayloadMeta;
  direct?: boolean;
}

const algorithms: Array<{
  id: AlgorithmId;
  name: string;
  short: string;
  description: string;
  badge: string;
}> = [
  {
    id: 'AES-256-GCM',
    name: 'AES-256-GCM',
    short: 'AES',
    description: '浏览器原生 Web Crypto，硬件加速设备上吞吐极高。',
    badge: 'Native',
  },
  {
    id: 'CHACHA20-POLY1305',
    name: 'ChaCha20-Poly1305',
    short: 'ChaCha20',
    description: '基于 ARX 结构的现代流密码 AEAD，适合跨设备使用。',
    badge: 'WASM',
  },
];

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** index;
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
};

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function copyText(value: string, label: string) {
  try {
    await navigator.clipboard.writeText(value);
    toast.success(`${label}已复制`);
  } catch {
    toast.error(`无法复制${label}，请检查浏览器剪贴板权限`);
  }
}

/** 解析 #chat / #chat=<房间码[.预共享密钥]> / Parse #chat / #chat=<room[.psk]> */
function parseChatHash(): { chat: boolean; room?: string } {
  const hash = window.location.hash;
  if (hash === '#chat') return { chat: true };
  const match = /^#chat=([A-Za-z0-9_-]{16,64}(?:\.[A-Za-z0-9_-]{20,64})?)$/.exec(hash);
  return match ? { chat: true, room: match[1] } : { chat: false };
}

export default function App() {
  const [legacyExchangeRequested] = useState(() => window.location.hash === '#exchange');
  const [initialChatRoom, setInitialChatRoom] = useState<string | undefined>(() => parseChatHash().room);
  const [tool, setTool] = useState<ToolMode>(() => {
    if (parseChatHash().chat) return 'chat';
    if (window.location.hash === '#integrity') return 'integrity';
    return 'vault';
  });
  const [theme, setTheme] = useState<ThemeMode>(() => document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');
  const [operation, setOperation] = useState<Operation>('encrypt');
  const [mode, setMode] = useState<InputMode>('text');
  const [algorithm, setAlgorithm] = useState<AlgorithmId>('AES-256-GCM');
  const [keyMode, setKeyMode] = useState<KeyMode>('raw');
  const [keyValue, setKeyValue] = useState(() => bytesToBase64Url(generateKey()));
  const [passphrase, setPassphrase] = useState('');
  const [passphraseConfirm, setPassphraseConfirm] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [fingerprint, setFingerprint] = useState('');
  const [keyValid, setKeyValid] = useState(true);
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedFileFormat, setSelectedFileFormat] = useState<FileFormat>('legacy');
  const [fileResult, setFileResult] = useState<FileResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [streamProgress, setStreamProgress] = useState<StreamProgress | null>(null);
  const [dragging, setDragging] = useState(false);
  const [lastMeta, setLastMeta] = useState<PayloadMeta | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const cancelRequested = useRef(false);
  const lastProgressUpdate = useRef(0);
  const fileInspectionId = useRef(0);
  const chatWarmed = useRef(false);
  const resultCleanupRef = useRef<(() => Promise<void>) | undefined>(undefined);

  const warmChat = () => {
    if (chatWarmed.current) return;
    chatWarmed.current = true;
    void loadChat();
  };

  useEffect(() => {
    const connection = (navigator as Navigator & { connection?: { saveData?: boolean } }).connection;
    if (connection?.saveData) return;
    const timer = window.setTimeout(warmChat, 3000);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    const syncTool = () => {
      const chatHash = parseChatHash();
      if (chatHash.chat) {
        setTool('chat');
        setInitialChatRoom(chatHash.room);
      } else if (window.location.hash === '#integrity') setTool('integrity');
      else {
        setTool('vault');
        if (window.location.hash === '#exchange') window.history.replaceState(null, '', '#vault');
      }
    };
    if (window.location.hash === '#exchange') window.history.replaceState(null, '', '#vault');
    window.addEventListener('hashchange', syncTool);
    return () => window.removeEventListener('hashchange', syncTool);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme === 'light' ? 'only light' : 'only dark';
    document.documentElement.style.backgroundColor = theme === 'light' ? '#f1f3f6' : '#08090b';
    try {
      localStorage.setItem('crypto-toolkit-theme', theme);
    } catch {
      // 严格隐私模式下持久化存储可能不可用 / Persistent storage may be unavailable in strict privacy modes.
    }
    document.querySelector('meta[name="theme-color"]')?.setAttribute(
      'content',
      theme === 'light' ? '#f1f3f6' : '#08090b',
    );
  }, [theme]);

  useEffect(() => () => {
    const cleanup = resultCleanupRef.current;
    resultCleanupRef.current = undefined;
    if (cleanup) void cleanup();
  }, []);

  const changeTool = (next: ToolMode) => {
    setTool(next);
    const hash =
      next === 'integrity' ? '#integrity'
      : next === 'chat' ? '#chat'
      : '#vault';
    window.history.replaceState(null, '', hash);
    if (next !== 'chat') setInitialChatRoom(undefined);
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    window.scrollTo({ top: 0, behavior: reducedMotion ? 'auto' : 'smooth' });
  };

  const useRecoveredKey = (key: string) => {
    setKeyMode('raw');
    setKeyValue(key);
    setOperation('decrypt');
    resetResult();
  };

  useEffect(() => {
    let active = true;
    try {
      const key = parseKey(keyValue);
      setKeyValid(true);
      void keyFingerprint(key).then((value) => {
        if (active) setFingerprint(value);
      });
    } catch {
      setKeyValid(false);
      setFingerprint('—');
    }
    return () => {
      active = false;
    };
  }, [keyValue]);

  const passphraseValid = passphrase.length > 0 && (operation === 'decrypt' || passphrase === passphraseConfirm);
  const credentialValid = keyMode === 'raw' ? keyValid : passphraseValid;
  const streamingSupported = supportsStreamingFileSave();
  const streamingUsesSystemPicker = usesSystemFilePickerForStreaming();

  const reportProgress = (progress: StreamProgress) => {
    const now = performance.now();
    if (progress.ratio < 1 && now - lastProgressUpdate.current < 100) return;
    lastProgressUpdate.current = now;
    setStreamProgress(progress);
  };

  const resetResult = () => {
    const cleanup = resultCleanupRef.current;
    resultCleanupRef.current = undefined;
    if (cleanup) void cleanup();
    setOutputText('');
    setFileResult(null);
    setLastMeta(null);
    setStreamProgress(null);
  };

  const changeOperation = (next: Operation) => {
    if (next === operation) return;
    setOperation(next);
    setInputText('');
    setSelectedFile(null);
    setSelectedFileFormat('legacy');
    resetResult();
  };

  const changeMode = (next: InputMode) => {
    if (next === mode) return;
    setMode(next);
    setInputText('');
    setSelectedFile(null);
    setSelectedFileFormat('legacy');
    resetResult();
  };

  const regenerateKey = () => {
    setKeyValue(bytesToBase64Url(generateKey()));
    setShowKey(false);
    resetResult();
    toast.success('已生成新的 256 位随机密钥');
  };

  const changeKeyMode = (next: KeyMode) => {
    if (next === keyMode) return;
    setKeyMode(next);
    setShowKey(false);
    resetResult();
  };

  const saveKey = () => {
    if (!keyValid) {
      toast.error('当前密钥格式无效');
      return;
    }
    const content = `Crypto Vault key\nFormat: Base64URL (256-bit)\nKey: ${keyValue.trim()}\nFingerprint: ${fingerprint}\n\nKeep this file private. Anyone with this key can decrypt matching ciphertext.\n`;
    downloadBlob(new Blob([content], { type: 'text/plain;charset=utf-8' }), 'crypto-vault.key.txt');
  };

  const resolveEncryptCredential = async (): Promise<{ key: Uint8Array; kdf: KeyDerivationInfo }> => {
    if (keyMode === 'raw') return { key: parseKey(keyValue), kdf: { type: 'raw' } };
    if (!passphraseValid) throw new Error(passphrase.length === 0 ? '请输入文本口令。' : '两次输入的文本口令不一致。');
    const kdf = createPassphraseKdf();
    const key = await derivePassphraseKey(passphrase, kdf, (ratio) => reportProgress({
      processed: 0,
      total: 0,
      ratio,
      bytesPerSecond: 0,
      phase: 'kdf',
    }));
    return { key, kdf };
  };

  const resolveDecryptCredential = async (packageBytes: Uint8Array): Promise<Uint8Array> => {
    const header = inspectPayloadHeader(packageBytes);
    if (header.keyDerivation?.type === 'argon2id') {
      if (keyMode !== 'passphrase') throw new Error('该密文使用文本口令，请切换到「文本口令」模式。');
      return derivePassphraseKey(passphrase, header.keyDerivation, (ratio) => reportProgress({
        processed: 0,
        total: 0,
        ratio,
        bytesPerSecond: 0,
        phase: 'kdf',
      }));
    }
    if (keyMode !== 'raw') throw new Error('该密文使用原始 256 位密钥，请切换到「256 位密钥」模式。');
    return parseKey(keyValue);
  };

  const handleFile = (file: File | undefined) => {
    if (!file) return;
    const inspectionId = ++fileInspectionId.current;
    setSelectedFile(file);
    setFileResult(null);
    setLastMeta(null);
    if (operation === 'decrypt') {
      setSelectedFileFormat('checking');
      void inspectStreamingFile(file)
        .then(() => {
          if (inspectionId === fileInspectionId.current) setSelectedFileFormat('stream');
        })
        .catch(() => {
          if (inspectionId === fileInspectionId.current) setSelectedFileFormat('legacy');
        });
    } else {
      setSelectedFileFormat(file.size >= STREAM_THRESHOLD_BYTES ? 'stream' : 'legacy');
    }
  };

  const processText = async () => {
    if (!inputText) throw new Error(operation === 'encrypt' ? '请输入需要加密的文本。' : '请输入需要解密的密文。');

    if (operation === 'encrypt') {
      const { key, kdf } = await resolveEncryptCredential();
      try {
        const plaintext = utf8(inputText);
        const encrypted = await encryptPayload(plaintext, key, {
          algorithm,
          kind: 'text',
          mime: 'text/plain;charset=utf-8',
        }, kdf);
        setOutputText(packageBytesToText(encrypted));
        setLastMeta({
          algorithm,
          kind: 'text',
          mime: 'text/plain;charset=utf-8',
          size: plaintext.byteLength,
          createdAt: new Date().toISOString(),
        });
        toast.success('文本已加密');
      } finally {
        key.fill(0);
      }
      return;
    }

    const packageBytes = textToPackageBytes(inputText);
    const key = await resolveDecryptCredential(packageBytes);
    try {
      const decrypted = await decryptPayload(packageBytes, key);
      if (decrypted.meta.kind !== 'text') throw new Error('该密文包含文件数据，请切换到文件模式解密。');
      setOutputText(decodeUtf8(decrypted.data));
      setLastMeta(decrypted.meta);
      toast.success('文本已通过认证并解密');
    } finally {
      key.fill(0);
    }
  };

  const processFile = async () => {
    if (!selectedFile) throw new Error('请选择一个文件。');
    const useStreaming = operation === 'encrypt'
      ? selectedFile.size >= STREAM_THRESHOLD_BYTES
      : selectedFileFormat === 'stream';

    if (operation === 'decrypt' && selectedFileFormat === 'checking') {
      throw new Error('仍在识别密文格式，请稍后重试。');
    }
    if (operation === 'decrypt' && selectedFileFormat === 'legacy' && selectedFile.size >= STREAM_THRESHOLD_BYTES) {
      throw new Error('该文件是旧版 V1 整体 AEAD 容器，无法低内存流式解密。V2 流式容器可处理多 GB 文件。');
    }

    if (useStreaming) {
      if (!streamingSupported) {
        throw new Error('该文件将使用流式模式，但当前浏览器不支持直接流式保存。请使用最新版 Chrome / Edge / Chromium。');
      }
      if (operation === 'encrypt') {
        const rawKey = keyMode === 'raw' ? parseKey(keyValue) : undefined;
        try {
          const result = await encryptFileStreaming(selectedFile, {
            algorithm,
            rawKey,
            passphrase: keyMode === 'passphrase' ? passphrase : undefined,
            onProgress: reportProgress,
            shouldCancel: () => cancelRequested.current,
          });
          const meta: PayloadMeta = result;
          resultCleanupRef.current = result.cleanup;
          setFileResult({
            name: result.savedAs,
            meta,
            direct: result.storage === 'direct',
            blob: result.exportFile,
          });
          setLastMeta(meta);
          toast.success(result.storage === 'direct' ? '超大文件已分块加密并保存' : '加密完成，请下载加密文件');
        } finally {
          rawKey?.fill(0);
        }
        return;
      }

      const rawKey = keyMode === 'raw' ? parseKey(keyValue) : undefined;
      try {
        const result = await decryptFileStreaming(selectedFile, {
          rawKey,
          passphrase: keyMode === 'passphrase' ? passphrase : undefined,
          onProgress: reportProgress,
          shouldCancel: () => cancelRequested.current,
        });
        const meta: PayloadMeta = result;
        resultCleanupRef.current = result.cleanup;
        setFileResult({
          name: result.savedAs,
          meta,
          direct: result.storage === 'direct',
          blob: result.exportFile,
        });
        setLastMeta(meta);
        toast.success(result.storage === 'direct' ? '超大文件已完成认证解密并保存' : '解密完成，请下载文件');
      } finally {
        rawKey?.fill(0);
      }
      return;
    }

    const data = new Uint8Array(await selectedFile.arrayBuffer());

    if (operation === 'encrypt') {
      const { key, kdf } = await resolveEncryptCredential();
      try {
        const encrypted = await encryptPayload(data, key, {
          algorithm,
          kind: 'file',
          name: selectedFile.name,
          mime: selectedFile.type || 'application/octet-stream',
        }, kdf);
        const meta: PayloadMeta = {
          algorithm,
          kind: 'file',
          name: selectedFile.name,
          mime: selectedFile.type || 'application/octet-stream',
          size: data.byteLength,
          createdAt: new Date().toISOString(),
        };
        setFileResult({
          blob: new Blob([new Uint8Array(encrypted).buffer], { type: 'application/x-crypta' }),
          name: `${selectedFile.name}.crypta`,
          meta,
        });
        setLastMeta(meta);
        toast.success('文件已加密，可安全下载');
      } finally {
        key.fill(0);
      }
      return;
    }

    const key = await resolveDecryptCredential(data);
    try {
      const decrypted = await decryptPayload(data, key);
      if (decrypted.meta.kind !== 'file') throw new Error('该密文包含文本数据，请切换到文本模式解密。');
      setFileResult({
        blob: new Blob([new Uint8Array(decrypted.data).buffer], { type: decrypted.meta.mime || 'application/octet-stream' }),
        name: decrypted.meta.name || selectedFile.name.replace(/\.crypta$/u, '') || 'decrypted.bin',
        meta: decrypted.meta,
      });
      setLastMeta(decrypted.meta);
      toast.success('文件已通过认证并解密');
    } finally {
      key.fill(0);
    }
  };

  const process = async () => {
    cancelRequested.current = false;
    setBusy(true);
    try {
      // 上一次 OPFS 导出由当前页面持有；开始新任务前先确定完成回收，
      // 避免配额估算与异步删除产生竞争。
      // The previous OPFS export is held by this page; finish its cleanup before a new task
      // so quota estimation never races with async deletion.
      const cleanup = resultCleanupRef.current;
      resultCleanupRef.current = undefined;
      if (cleanup) await cleanup();
      resetResult();
      if (mode === 'text') await processText();
      else await processFile();
    } catch (error) {
      if (error instanceof SavePickerCancelledError) toast.info('未选择保存位置，未开始加密');
      else if (error instanceof StreamUserCancelledError) toast.info('已停止并丢弃未完成文件');
      else if (error instanceof DOMException && error.name === 'AbortError') {
        toast.error(`操作被浏览器中止${error.message ? `：${error.message}` : ''}`);
      } else toast.error(error instanceof Error ? error.message : '处理失败，请检查输入。');
    } finally {
      setBusy(false);
    }
  };

  const actionLabel = operation === 'encrypt' ? '开始加密' : '开始解密';
  const outputLabel = operation === 'encrypt' ? '加密结果' : '解密结果';
  const usesStreamingFile = mode === 'file' && !!selectedFile && (
    (operation === 'encrypt' && selectedFile.size >= STREAM_THRESHOLD_BYTES) ||
    (operation === 'decrypt' && selectedFileFormat === 'stream')
  );
  const primaryLabel = usesStreamingFile
    ? streamingUsesSystemPicker
      ? operation === 'encrypt' ? '选择保存位置并加密' : '选择保存位置并解密'
      : operation === 'encrypt' ? '开始流式加密' : '开始流式解密'
    : actionLabel;
  const actionDisabled =
    busy ||
    !credentialValid ||
    (mode === 'file' ? !selectedFile : !inputText) ||
    (operation === 'decrypt' && mode === 'file' && selectedFileFormat === 'checking');
  const showStreamCancel = busy && mode === 'file' && !!selectedFile && (
    (operation === 'encrypt' && selectedFile.size >= STREAM_THRESHOLD_BYTES) ||
    (operation === 'decrypt' && selectedFileFormat === 'stream')
  );
  const renderActionDock = (variant: 'inline' | 'mobile') => (
    <div className={`action-dock action-dock-${variant}`}>
      <button
        className="primary-action"
        type="button"
        onClick={() => void process()}
        disabled={actionDisabled}
      >
        {busy ? <RefreshCw className="spin" size={18} /> : operation === 'encrypt' ? <LockKeyhole size={18} /> : <UnlockKeyhole size={18} />}
        <span>{busy ? '正在处理…' : primaryLabel}</span>
        {!busy && <ArrowRight size={17} />}
      </button>
      {showStreamCancel && (
        <button className="cancel-action" type="button" onClick={() => { cancelRequested.current = true; }}>
          <X size={15} /> 取消并丢弃未完成写入
        </button>
      )}
    </div>
  );

  return (
    <main className={`page-shell ${tool === 'vault' ? 'vault-page' : tool === 'integrity' ? 'integrity-page' : 'chat-page'}`}>
      <Toaster
        position="top-center"
        richColors
        theme={theme}
        toastOptions={{ duration: 2600 }}
      />
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      <header className="topbar">
        <a className="brand" href="#vault" onClick={(event) => { event.preventDefault(); changeTool('vault'); }} aria-label="密码学工具首页">
          <span className="brand-mark"><ShieldCheck size={19} strokeWidth={2.2} /></span>
          <span>Crypto Toolkit</span>
        </a>
        <div className="topbar-actions">
          <nav className="tool-switch" aria-label="密码学工具">
            <button type="button" className={tool === 'vault' ? 'active' : ''} onClick={() => changeTool('vault')}><LockKeyhole size={14} /> 加密工具</button>
            <button type="button" className={tool === 'integrity' ? 'active' : ''} onClick={() => changeTool('integrity')} onPointerEnter={() => void loadIntegrityChecker()} onFocus={() => void loadIntegrityChecker()}><FileCheck2 size={14} /> 完整性校验</button>
            <button type="button" className={tool === 'chat' ? 'active' : ''} onClick={() => changeTool('chat')} onPointerEnter={warmChat} onFocus={warmChat}><MessageSquareLock size={14} /> 加密私聊</button>
          </nav>
          <a
            className="repo-link blog-link"
            href="https://www.minayuki.co/"
            aria-label="返回 Minayuki 博客"
            title="返回博客"
          >
            <ArrowLeft size={16} />
            <span>返回博客</span>
          </a>
          <a
            className="repo-link"
            href="https://github.com/1878580314/crypto-vault"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="在 GitHub 查看 Crypto Vault 开源仓库"
            title="GitHub 开源仓库"
          >
            <GitFork size={16} />
            <span>开源仓库</span>
          </a>
          <button
            type="button"
            className="theme-toggle"
            onClick={() => setTheme((value) => value === 'dark' ? 'light' : 'dark')}
            aria-label={theme === 'dark' ? '切换到白天模式' : '切换到夜间模式'}
            title={theme === 'dark' ? '白天模式' : '夜间模式'}
          >
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </div>
      </header>

      {tool === 'chat' ? (
        <Suspense fallback={<div className="chat-suspense"><Loader2 className="spin" size={18} /> 正在载入加密模块…</div>}>
          <Chat key={initialChatRoom ?? 'lobby'} initialRoom={initialChatRoom} />
        </Suspense>
      ) : tool === 'integrity' ? (
        <Suspense fallback={<div className="tool-suspense"><Loader2 className="spin" size={18} /> 正在载入完整性模块…</div>}>
          <IntegrityChecker />
        </Suspense>
      ) : <>
      <section className="hero">
        <h1>敏感数据加密</h1>
        <p>AES-256-GCM 与 ChaCha20-Poly1305 本地认证加密，支持文本、文件与多 GB 流式处理。</p>
      </section>

      <section className="workspace-card">
        <div className="operation-tabs" role="tablist" aria-label="操作模式">
          <button
            type="button"
            className={operation === 'encrypt' ? 'active' : ''}
            onClick={() => changeOperation('encrypt')}
            role="tab"
            aria-selected={operation === 'encrypt'}
          >
            <LockKeyhole size={17} /> 加密
          </button>
          <button
            type="button"
            className={operation === 'decrypt' ? 'active' : ''}
            onClick={() => changeOperation('decrypt')}
            role="tab"
            aria-selected={operation === 'decrypt'}
          >
            <UnlockKeyhole size={17} /> 解密
          </button>
        </div>

        <div className="workspace-grid">
          <div className="main-panel">
            <section className="section-block">
              <div className="section-heading">
                <div>
                  <span className="step-number">01</span>
                  <h2>{operation === 'encrypt' ? '选择加密算法' : '算法自动识别'}</h2>
                </div>
              </div>

              {operation === 'encrypt' ? (
                <div className="algorithm-grid">
                  {algorithms.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      className={`algorithm-card ${algorithm === item.id ? 'selected' : ''}`}
                      onClick={() => setAlgorithm(item.id)}
                    >
                      <div className="algorithm-topline">
                        <span className="algorithm-icon">{item.id === 'AES-256-GCM' ? <Zap size={18} /> : <Binary size={18} />}</span>
                        <span className="algorithm-badge">{item.badge}</span>
                      </div>
                      <strong>{item.name}</strong>
                      <p>{item.description}</p>
                      <span className="radio-dot" aria-hidden="true"><span /></span>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="auto-detect-card">
                  <div className="auto-icon"><Fingerprint size={22} /></div>
                  <div>
                    <strong>从认证元数据读取算法</strong>
                  </div>
                </div>
              )}
            </section>

            <section className="section-block input-section">
              <div className="section-heading input-heading">
                <div>
                  <span className="step-number">02</span>
                  <h2>{operation === 'encrypt' ? '添加内容' : '载入密文'}</h2>
                </div>
                <div className="mode-switch" role="tablist" aria-label="内容类型">
                <button type="button" role="tab" aria-selected={mode === 'text'} className={mode === 'text' ? 'active' : ''} onClick={() => changeMode('text')}>
                    <FileText size={14} /> 文本
                  </button>
                <button type="button" role="tab" aria-selected={mode === 'file'} className={mode === 'file' ? 'active' : ''} onClick={() => changeMode('file')}>
                    <FileUp size={14} /> 文件
                  </button>
                </div>
              </div>

              {mode === 'text' ? (
                <div className="textarea-wrap">
                  <textarea
                    value={inputText}
                    onChange={(event) => {
                      setInputText(event.target.value);
                      resetResult();
                    }}
                    placeholder={operation === 'encrypt' ? '输入需要加密的文本…' : '粘贴 crypta:v1: 开头的密文…'}
                    aria-label={operation === 'encrypt' ? '需要加密的文本' : '需要解密的文本密文'}
                    spellCheck={false}
                  />
                  <span className="char-count">{inputText.length.toLocaleString()} 字符</span>
                </div>
              ) : (
                <>
                  <div
                    className={`dropzone ${dragging ? 'dragging' : ''} ${selectedFile ? 'has-file' : ''}`}
                    onDragOver={(event) => {
                      event.preventDefault();
                      setDragging(true);
                    }}
                    onDragLeave={() => setDragging(false)}
                    onDrop={(event) => {
                      event.preventDefault();
                      setDragging(false);
                      handleFile(event.dataTransfer.files[0]);
                    }}
                    onClick={() => !selectedFile && fileInputRef.current?.click()}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(event) => {
                      if (!selectedFile && (event.key === 'Enter' || event.key === ' ')) fileInputRef.current?.click();
                    }}
                  >
                    <input
                      ref={fileInputRef}
                      className="hidden-input"
                      type="file"
                      accept={operation === 'decrypt' ? '.crypta,application/x-crypta,application/octet-stream' : undefined}
                      onChange={(event) => handleFile(event.target.files?.[0])}
                    />
                    {selectedFile ? (
                      <div className="selected-file">
                        <span className="file-icon"><FileArchive size={22} /></span>
                        <div className="file-details">
                          <strong title={selectedFile.name}>{selectedFile.name}</strong>
                          <span>{formatBytes(selectedFile.size)} · {selectedFile.type || 'binary'}</span>
                        </div>
                        <button
                          type="button"
                          className="icon-button"
                          aria-label="移除文件"
                          onClick={(event) => {
                            event.stopPropagation();
                            fileInspectionId.current += 1;
                            setSelectedFile(null);
                            setSelectedFileFormat('legacy');
                            resetResult();
                            if (fileInputRef.current) fileInputRef.current.value = '';
                          }}
                        >
                          <X size={17} />
                        </button>
                      </div>
                    ) : (
                      <>
                        <span className="upload-icon"><FileUp size={23} /></span>
                        <strong>{operation === 'encrypt' ? '拖放任意文件到这里' : '拖放 .crypta 密文到这里'}</strong>
                        <p>或点击选择</p>
                      </>
                    )}
                  </div>
                  {selectedFile && (
                    (operation === 'encrypt' && selectedFile.size >= STREAM_THRESHOLD_BYTES) ||
                    (operation === 'decrypt' && selectedFileFormat === 'stream')
                  ) && (
                    <div className={`streaming-hint ${streamingSupported ? '' : 'unsupported'}`}>
                      <Zap size={14} />
                      <span>
                        {streamingSupported
                          ? streamingUsesSystemPicker
                            ? `V2 · ${formatBytes(STREAM_CHUNK_BYTES)} · 并行流水线`
                            : `V2 · Worker + OPFS · ${formatBytes(STREAM_CHUNK_BYTES)}`
                          : '当前浏览器不支持多 GB 流式处理'}
                      </span>
                    </div>
                  )}
                  {selectedFile && operation === 'decrypt' && selectedFileFormat === 'checking' && (
                    <div className="streaming-hint"><RefreshCw className="spin" size={14} /><span>正在识别 CRYPTA V1 / V2 STREAM 格式…</span></div>
                  )}
                </>
              )}
            </section>

            <section className="section-block key-section">
              <div className="section-heading">
                <div>
                  <span className="step-number">03</span>
                  <h2>密钥凭据</h2>
                </div>
                {keyMode === 'raw' && (
                  <button type="button" className="text-button" onClick={regenerateKey}>
                    <RefreshCw size={14} /> 随机生成
                  </button>
                )}
              </div>

              <div className="key-mode-switch" role="tablist" aria-label="密钥类型">
                <button type="button" role="tab" aria-selected={keyMode === 'raw'} className={keyMode === 'raw' ? 'active' : ''} onClick={() => changeKeyMode('raw')}>
                  <KeyRound size={14} /> 256 位密钥
                </button>
                <button type="button" role="tab" aria-selected={keyMode === 'passphrase'} className={keyMode === 'passphrase' ? 'active' : ''} onClick={() => changeKeyMode('passphrase')}>
                  <FileKey2 size={14} /> 文本口令
                </button>
              </div>

              {keyMode === 'raw' ? (
                <>
                  <div className={`key-input-shell ${keyValid ? '' : 'invalid'}`}>
                    <KeyRound size={17} />
                    <input
                      value={keyValue}
                      onChange={(event) => {
                        setKeyValue(event.target.value);
                        resetResult();
                      }}
                      type={showKey ? 'text' : 'password'}
                      aria-label="256 位加密密钥"
                      autoComplete="off"
                      spellCheck={false}
                    />
                    <button type="button" onClick={() => setShowKey((value) => !value)} aria-label={showKey ? '隐藏密钥' : '显示密钥'}>
                      {showKey ? <EyeOff size={17} /> : <Eye size={17} />}
                    </button>
                    <button type="button" onClick={() => void copyText(keyValue, '密钥')} aria-label="复制密钥">
                      <Copy size={17} />
                    </button>
                    <button type="button" onClick={saveKey} aria-label="下载密钥">
                      <Download size={17} />
                    </button>
                  </div>
                  <div className="key-meta-row">
                    <span className={keyValid ? 'valid' : 'invalid-text'}>
                      {keyValid ? <><Check size={13} /> 256-bit · Base64URL / Hex</> : '需要 32 字节密钥'}
                    </span>
                    <span className="fingerprint"><Fingerprint size={12} /> {fingerprint}</span>
                  </div>
                  <div className="key-warning">
                    <ShieldCheck size={15} />
                    <span>请与密文分开保存。</span>
                  </div>
                </>
              ) : (
                <>
                  <div className={`key-input-shell ${passphrase.length > 0 ? '' : 'invalid'}`}>
                    <FileKey2 size={17} />
                    <input
                      value={passphrase}
                      onChange={(event) => {
                        setPassphrase(event.target.value);
                        resetResult();
                      }}
                      type={showKey ? 'text' : 'password'}
                      aria-label="文本口令"
                      placeholder="输入任意非空 UTF-8 文本"
                      autoComplete="new-password"
                      spellCheck={false}
                    />
                    <button type="button" onClick={() => setShowKey((value) => !value)} aria-label={showKey ? '隐藏口令' : '显示口令'}>
                      {showKey ? <EyeOff size={17} /> : <Eye size={17} />}
                    </button>
                    <button type="button" onClick={() => void copyText(passphrase, '文本口令')} aria-label="复制文本口令">
                      <Copy size={17} />
                    </button>
                  </div>
                  {operation === 'encrypt' && (
                    <div className={`key-input-shell confirm-shell ${passphraseConfirm === passphrase && passphrase.length > 0 ? '' : 'invalid'}`}>
                      <Check size={17} />
                      <input
                        value={passphraseConfirm}
                        onChange={(event) => {
                          setPassphraseConfirm(event.target.value);
                          resetResult();
                        }}
                        type={showKey ? 'text' : 'password'}
                        aria-label="确认文本口令"
                        placeholder="再次输入，防止加密时输错"
                        autoComplete="new-password"
                        spellCheck={false}
                      />
                    </div>
                  )}
                  <div className="key-meta-row">
                    <span className={passphraseValid ? 'valid' : 'invalid-text'}>
                      {passphraseValid ? <><Check size={13} /> Argon2id · 64 MiB · 3 passes</> : operation === 'encrypt' && passphrase.length > 0 ? '两次口令必须完全一致' : '口令不能为空'}
                    </span>
                    <span className="fingerprint">16-byte random salt</span>
                  </div>
                  <div className="key-warning passphrase-warning">
                    <ShieldCheck size={15} />
                    <span>Argon2id 派生；建议使用长随机短语。</span>
                  </div>
                </>
              )}

              <KeyExchange
                operation={operation}
                currentKey={keyValue}
                keyMode={keyMode}
                initiallyExpanded={legacyExchangeRequested}
                onRequireRawKey={() => {
                  setKeyMode('raw');
                  resetResult();
                }}
                onUseRecoveredKey={useRecoveredKey}
              />
            </section>

            {busy && streamProgress && (
              <div
                className="progress-card"
                role="progressbar"
                aria-label={streamProgress.phase === 'kdf' ? '密钥派生进度' : '文件处理进度'}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={Math.round(streamProgress.ratio * 100)}
              >
                <div className="progress-topline">
                  <span>{streamProgress.phase === 'kdf' ? '正在派生 256 位密钥' : '正在流式处理文件'}</span>
                  <strong>{Math.round(streamProgress.ratio * 100)}%</strong>
                </div>
                <div className="progress-track"><span style={{ width: `${streamProgress.ratio * 100}%` }} /></div>
                <div className="progress-meta">
                  <span>{streamProgress.phase === 'data' ? `${formatBytes(streamProgress.processed)} / ${formatBytes(streamProgress.total)}` : 'Argon2id memory-hard KDF'}</span>
                  <span>{streamProgress.phase === 'data' && streamProgress.bytesPerSecond > 0 ? `${formatBytes(streamProgress.bytesPerSecond)}/s` : '本地计算'}</span>
                </div>
                {streamProgress.phase === 'data' && streamProgress.cryptoBytesPerSecond !== undefined && (
                  <div className="progress-stages">
                    <span>读取 {formatBytes(streamProgress.readBytesPerSecond ?? 0)}/s</span>
                    <span>AEAD {formatBytes(streamProgress.cryptoBytesPerSecond)}/s{streamProgress.concurrency && streamProgress.concurrency > 1 ? ` ×${streamProgress.concurrency}` : ''}</span>
                    <span>写入 {formatBytes(streamProgress.writeBytesPerSecond ?? 0)}/s</span>
                  </div>
                )}
              </div>
            )}

            {renderActionDock('inline')}

            {(outputText || fileResult) && (
              <section className="result-card">
                <div className="result-heading">
                  <div>
                    <span className="success-icon"><Check size={15} /></span>
                    <div>
                      <strong>{outputLabel}</strong>
                      <span>{lastMeta?.algorithm}</span>
                    </div>
                  </div>
                  {outputText && (
                    <button type="button" className="secondary-button" onClick={() => void copyText(outputText, outputLabel)}>
                      <Clipboard size={14} /> 复制
                    </button>
                  )}
                </div>
                {outputText ? (
                  <textarea className="result-text" value={outputText} readOnly spellCheck={false} />
                ) : fileResult ? (
                  <div className="result-file-row">
                    <span className="file-icon result"><FileKey2 size={21} /></span>
                    <div>
                      <strong>{fileResult.name}</strong>
                      <span>{fileResult.direct ? '已直接写入磁盘' : fileResult.blob ? formatBytes(fileResult.blob.size) : '已完成'}</span>
                    </div>
                    {fileResult.blob && (
                      <button type="button" className="download-button" onClick={() => downloadBlob(fileResult.blob!, fileResult.name)}>
                        <Download size={15} /> 下载文件
                      </button>
                    )}
                  </div>
                ) : null}
              </section>
            )}
          </div>

          <aside className="side-panel">
            <div className="security-card">
              <div className="security-orbit">
                <div className="orbit-ring ring-one" />
                <div className="orbit-ring ring-two" />
                <ShieldCheck size={28} />
              </div>
              <span className="status-dot"><span /> LOCAL ONLY</span>
              <h3>你的数据不会离开浏览器</h3>
            </div>

            <div className="spec-list">
              <div>
                <span className="spec-icon"><KeyRound size={15} /></span>
                <div><strong>256-bit Key</strong><span>CSPRNG / Argon2id 派生</span></div>
              </div>
              <div>
                <span className="spec-icon"><Binary size={15} /></span>
                <div><strong>16 MiB Chunks</strong><span>超大文件恒定内存流式处理</span></div>
              </div>
              <div>
                <span className="spec-icon"><ShieldCheck size={15} /></span>
                <div><strong>128-bit Tag</strong><span>完整性与真实性校验</span></div>
              </div>
            </div>

          </aside>
        </div>
      </section>
      {renderActionDock('mobile')}
      </>}

      <footer>
        <span>Crypto Toolkit</span>
        <span>·</span>
        <span>Client-side cryptography</span>
      </footer>
    </main>
  );
}
