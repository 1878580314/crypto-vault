import {
  Check,
  Clipboard,
  Copy,
  Download,
  FileCheck2,
  FilePlus2,
  FolderOpen,
  Hash,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { toast } from 'sonner';
import {
  ALGORITHM_SPECS,
  DEFAULT_ALGORITHMS,
  matchesManifestEntry,
  normalizeAlgorithms,
  parseManifest,
  type AlgorithmId,
  type IntegrityManifest,
  type ManifestEntry,
} from './integrity';

type RowState = {
  id: string;
  file: File;
  path: string;
  hashes?: Record<string, string>;
  error?: string;
  active?: boolean;
};

type ProgressState = {
  index: number;
  fileProcessed: number;
  fileSize: number;
  totalProcessed: number;
  totalBytes: number;
  bytesPerSecond: number;
  concurrency: number;
  hashBytesPerSecond?: number;
  ioWaitRatio?: number;
  backend?: string;
};

type ProgressDiagnostics = Pick<ProgressState, 'hashBytesPerSecond' | 'ioWaitRatio' | 'backend'> & {
  pipelineBytesPerSecond?: number;
};

const STORAGE_KEY = 'crypto-integrity-algorithms';

function loadStoredAlgorithms(): AlgorithmId[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const normalized = normalizeAlgorithms(JSON.parse(stored));
      if (normalized.length > 0) return normalized;
    }
  } catch {
    return [...DEFAULT_ALGORITHMS];
  }
  return [...DEFAULT_ALGORITHMS];
}

function filePath(file: File): string {
  const relative = (file as File & { webkitRelativePath?: string }).webkitRelativePath;
  return relative || file.name;
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** index;
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

function downloadText(name: string, text: string, type = 'application/json;charset=utf-8') {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
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

function computedHashIds(hashes: Record<string, string> | undefined): AlgorithmId[] {
  if (!hashes) return [];
  return ALGORITHM_SPECS.map((spec) => spec.id).filter((id) => typeof hashes[id] === 'string');
}

export default function IntegrityChecker() {
  const [rows, setRows] = useState<RowState[]>([]);
  const [algorithms, setAlgorithms] = useState<AlgorithmId[]>(loadStoredAlgorithms);
  const [manifest, setManifest] = useState<IntegrityManifest | null>(null);
  const [manifestName, setManifestName] = useState('');
  const [busy, setBusy] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState<ProgressState | null>(null);
  const filesInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const manifestInputRef = useRef<HTMLInputElement>(null);
  const workerRefs = useRef<Worker[]>([]);

  useEffect(() => () => {
    for (const worker of workerRefs.current) worker.terminate();
    workerRefs.current = [];
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(algorithms));
    } catch {
      return;
    }
  }, [algorithms]);

  const manifestByPath = useMemo(() => {
    const map = new Map<string, ManifestEntry>();
    for (const entry of manifest?.files ?? []) map.set(entry.path, entry);
    return map;
  }, [manifest]);

  const addFiles = (files: FileList | File[] | null) => {
    if (!files || busy) return;
    const incoming = Array.from(files);
    if (incoming.length === 0) return;
    setRows((current) => {
      const keys = new Set(current.map((row) => `${row.path}\0${row.file.size}\0${row.file.lastModified}`));
      const next = [...current];
      for (const file of incoming) {
        const path = filePath(file);
        const key = `${path}\0${file.size}\0${file.lastModified}`;
        if (keys.has(key)) continue;
        keys.add(key);
        next.push({ id: crypto.randomUUID?.() ?? `${Date.now()}-${next.length}`, file, path });
      }
      return next;
    });
  };

  const toggleAlgorithm = (id: AlgorithmId) => {
    if (busy) return;
    setAlgorithms((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);
  };

  const allSelected = algorithms.length === ALGORITHM_SPECS.length;
  const toggleAllAlgorithms = () => {
    if (busy) return;
    setAlgorithms(allSelected ? [...DEFAULT_ALGORITHMS] : ALGORITHM_SPECS.map((spec) => spec.id));
  };

  const statusFor = (row: RowState): 'idle' | 'hashing' | 'ready' | 'match' | 'mismatch' | 'unlisted' | 'error' => {
    if (row.error) return 'error';
    if (row.active) return 'hashing';
    if (!row.hashes) return 'idle';
    if (!manifest) return 'ready';
    const expected = manifestByPath.get(row.path);
    if (!expected) return 'unlisted';
    if (expected.size !== undefined && expected.size !== row.file.size) return 'mismatch';
    return matchesManifestEntry(expected, row.hashes) ? 'match' : 'mismatch';
  };

  const counts = useMemo(() => {
    const result = { match: 0, mismatch: 0, unlisted: 0, ready: 0, pending: 0 };
    for (const row of rows) {
      const status = statusFor(row);
      if (status === 'match') result.match += 1;
      else if (status === 'mismatch' || status === 'error') result.mismatch += 1;
      else if (status === 'unlisted') result.unlisted += 1;
      else if (status === 'ready') result.ready += 1;
      else result.pending += 1;
    }
    return result;
  }, [rows, manifest, manifestByPath]);

  const missingCount = useMemo(() => {
    if (!manifest) return 0;
    const selected = new Set(rows.map((row) => row.path));
    return manifest.files.reduce((count, entry) => count + (selected.has(entry.path) ? 0 : 1), 0);
  }, [manifest, rows]);

  const startHashing = () => {
    if (rows.length === 0 || busy || algorithms.length === 0) return;
    const isMobile = typeof navigator !== 'undefined' && (
      (navigator as Navigator & { userAgentData?: { mobile?: boolean } }).userAgentData?.mobile === true ||
      /Android|iPhone|iPad|iPod|Mobile/iu.test(navigator.userAgent)
    );
    const cores = Math.max(1, navigator.hardwareConcurrency || 4);
    const averageFileBytes = rows.reduce((sum, row) => sum + row.file.size, 0) / rows.length;
    const largestFileBytes = Math.max(...rows.map((row) => row.file.size));
    const blake3Only = algorithms.length === 1 && algorithms[0] === 'BLAKE3';
    const largeSequentialWorkload = averageFileBytes >= 128 * 1024 * 1024 || largestFileBytes >= 256 * 1024 * 1024;

    // BLAKE3 SIMD 吞吐远高于浏览器 File/Blob I/O：大文件按核数扩 Worker 会让多文件 read-ahead
    // 争抢同一存储设备、破坏顺序吞吐；小文件批量仍保留较高并行度，以隐藏打开文件等固定延迟。
    // BLAKE3 SIMD outpaces browser File/Blob I/O: scaling workers by core count on large files
    // lets read-ahead fight over one device and hurts sequential throughput; small batches
    // keep higher parallelism to hide fixed open/provider latencies.
    const desiredConcurrency = blake3Only && largeSequentialWorkload
      ? isMobile ? 1 : 2
      : isMobile
        ? cores >= 4 ? 2 : 1
        : cores >= 12 ? 4 : cores >= 8 ? 3 : cores >= 4 ? 2 : 1;
    const concurrency = Math.max(1, Math.min(rows.length, desiredConcurrency));

    for (const worker of workerRefs.current) worker.terminate();
    workerRefs.current = [];
    setBusy(true);
    setCancelling(false);
    setProgress(null);
    setRows((current) => current.map((row) => ({ ...row, hashes: undefined, error: undefined, active: false })));

    const files = rows.map((row) => row.file);
    const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
    const processedByIndex = new Array<number>(files.length).fill(0);
    const diagnosticsByIndex = new Array<ProgressDiagnostics | undefined>(files.length).fill(undefined);
    const startedAt = performance.now();
    let totalProcessed = 0;
    let nextIndex = 0;
    let completed = 0;
    let failed = 0;
    let finished = false;

    const finish = (outcome: 'done' | 'cancelled' | 'error' = 'done') => {
      if (finished) return;
      finished = true;
      for (const worker of workerRefs.current) worker.terminate();
      workerRefs.current = [];
      setBusy(false);
      setCancelling(false);
      setRows((current) => current.map((row) => ({ ...row, active: false })));
      if (outcome === 'cancelled') {
        toast.info('批量校验已取消');
      } else if (outcome === 'error') {
        // 具体浏览器错误已由 worker 错误处理展示 / The worker error handler already displayed the concrete browser error.
      } else if (failed > 0) {
        toast.warning(`批量计算完成，${failed.toLocaleString()} 个文件失败`);
      } else {
        toast.success(manifest ? '批量完整性校验完成' : '哈希摘要计算完成');
      }
    };

    const dispatchNext = (worker: Worker) => {
      if (finished) return;
      if (nextIndex >= files.length) {
        if (completed >= files.length) finish();
        return;
      }
      const index = nextIndex;
      nextIndex += 1;
      worker.postMessage({ type: 'hash', index, file: files[index], algorithms });
    };

    const updateAggregateProgress = (
      index: number,
      fileProcessed: number,
      fileSize: number,
      diagnostics?: ProgressDiagnostics,
    ) => {
      if (diagnostics) {
        diagnosticsByIndex[index] = {
          ...diagnosticsByIndex[index],
          ...diagnostics,
        };
      }
      const resolvedDiagnostics = diagnosticsByIndex[index];
      const previous = processedByIndex[index] ?? 0;
      if (fileProcessed > previous) {
        totalProcessed += fileProcessed - previous;
        processedByIndex[index] = fileProcessed;
      }
      const elapsedSeconds = Math.max((performance.now() - startedAt) / 1000, 0.001);
      const aggregateBytesPerSecond = totalProcessed / elapsedSeconds;
      setProgress({
        index,
        fileProcessed,
        fileSize,
        totalProcessed,
        totalBytes,
        bytesPerSecond: concurrency === 1 && resolvedDiagnostics?.pipelineBytesPerSecond
          ? resolvedDiagnostics.pipelineBytesPerSecond
          : aggregateBytesPerSecond,
        concurrency,
        hashBytesPerSecond: resolvedDiagnostics?.hashBytesPerSecond,
        ioWaitRatio: resolvedDiagnostics?.ioWaitRatio,
        backend: resolvedDiagnostics?.backend,
      });
    };

    for (let slot = 0; slot < concurrency; slot += 1) {
      const worker = new Worker(new URL('./integrity.worker.ts', import.meta.url), {
        type: 'module',
        name: `crypta-digest-${slot + 1}`,
      });
      workerRefs.current.push(worker);

      worker.onerror = (event) => {
        if (finished) return;
        toast.error(event.message || '摘要 Worker 运行失败');
        finish('error');
      };

      worker.onmessage = (event: MessageEvent<Record<string, unknown>>) => {
        if (finished) return;
        const message = event.data;
        if (message.type === 'ready') {
          dispatchNext(worker);
          return;
        }
        if (message.type === 'file-start' && typeof message.index === 'number') {
          if (typeof message.backend === 'string') {
            diagnosticsByIndex[message.index] = {
              ...diagnosticsByIndex[message.index],
              backend: message.backend,
            };
          }
          setRows((current) => current.map((row, index) => index === message.index ? { ...row, active: true } : row));
          updateAggregateProgress(
            message.index,
            processedByIndex[message.index] ?? 0,
            files[message.index]?.size ?? 0,
          );
          return;
        }
        if (
          message.type === 'progress' &&
          typeof message.index === 'number' &&
          typeof message.fileProcessed === 'number' &&
          typeof message.fileSize === 'number'
        ) {
          updateAggregateProgress(message.index, message.fileProcessed, message.fileSize, {
            hashBytesPerSecond: typeof message.hashBytesPerSecond === 'number' ? message.hashBytesPerSecond : undefined,
            pipelineBytesPerSecond: typeof message.pipelineBytesPerSecond === 'number' ? message.pipelineBytesPerSecond : undefined,
            ioWaitRatio: typeof message.ioWaitRatio === 'number' ? message.ioWaitRatio : undefined,
            backend: typeof message.backend === 'string' ? message.backend : undefined,
          });
          return;
        }
        if (message.type === 'file' && typeof message.index === 'number' && message.hashes && typeof message.hashes === 'object') {
          const index = message.index;
          updateAggregateProgress(index, files[index]?.size ?? 0, files[index]?.size ?? 0);
          completed += 1;
          setRows((current) => current.map((row, rowIndex) => rowIndex === index ? { ...row, hashes: message.hashes as Record<string, string>, active: false } : row));
          dispatchNext(worker);
          return;
        }
        if (message.type === 'file-error' && typeof message.index === 'number') {
          const index = message.index;
          completed += 1;
          failed += 1;
          setRows((current) => current.map((row, rowIndex) => rowIndex === index ? {
            ...row,
            active: false,
            error: typeof message.message === 'string' ? message.message : '哈希计算失败',
          } : row));
          dispatchNext(worker);
          return;
        }
        if (message.type === 'cancelled') finish('cancelled');
      };
    }
  };

  const cancelHashing = () => {
    if (workerRefs.current.length === 0 || cancelling) return;
    setCancelling(true);
    for (const worker of workerRefs.current) worker.terminate();
    workerRefs.current = [];
    setRows((current) => current.map((row) => ({ ...row, active: false })));
    setBusy(false);
    setCancelling(false);
    toast.info('批量校验已取消');
  };

  const loadManifest = async (file?: File) => {
    if (!file) return;
    try {
      const parsed = parseManifest(await file.text());
      setManifest(parsed);
      setManifestName(file.name);
      setAlgorithms((current) => {
        const merged = new Set([...current, ...parsed.algorithms]);
        return ALGORITHM_SPECS.map((spec) => spec.id).filter((id) => merged.has(id));
      });
      toast.success(`已载入 ${parsed.files.length.toLocaleString()} 条校验记录`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '无法读取校验清单');
    } finally {
      if (manifestInputRef.current) manifestInputRef.current.value = '';
    }
  };

  const exportManifest = () => {
    const completed = rows.filter((row) => computedHashIds(row.hashes).length > 0);
    if (completed.length === 0) return;
    const exported = {
      format: 'CRYPTA-INTEGRITY',
      version: 2,
      createdAt: new Date().toISOString(),
      files: completed.map((row) => ({ path: row.path, size: row.file.size, hashes: row.hashes })),
    };
    downloadText('integrity-manifest.json', `${JSON.stringify(exported, null, 2)}\n`);
  };

  const copyRowHashes = (row: RowState) => {
    const ids = computedHashIds(row.hashes);
    if (ids.length === 0 || !row.hashes) return;
    const text = ids.length === 1
      ? row.hashes[ids[0]]!
      : ids.map((id) => `${id}: ${row.hashes![id]}`).join('\n');
    void copyText(text, ids.length === 1 ? `${ids[0]} 摘要` : '全部摘要');
  };

  const copyChecksums = () => {
    const completed = rows.filter((row) => computedHashIds(row.hashes).length > 0);
    if (completed.length === 0) return;
    const blocks: string[] = [];
    for (const spec of ALGORITHM_SPECS) {
      const lines = completed
        .filter((row) => row.hashes?.[spec.id])
        .map((row) => `${row.hashes![spec.id]} *${row.path}`);
      if (lines.length > 0) blocks.push(`# ${spec.id}\n${lines.join('\n')}`);
    }
    if (blocks.length > 0) void copyText(blocks.join('\n\n'), '校验摘要');
  };

  const removeRow = (id: string) => setRows((current) => current.filter((row) => row.id !== id));
  const totalSize = rows.reduce((sum, row) => sum + row.file.size, 0);
  const ratio = progress && progress.totalBytes > 0 ? progress.totalProcessed / progress.totalBytes : 0;

  return (
    <>
      <section className="hero integrity-hero">
        <h1>文件完整性校验</h1>
        <p>MD5、SHA-1/2/3、BLAKE2b、BLAKE3 批量摘要与清单验证。文件按块读取，所有计算仅在浏览器本地完成。</p>
      </section>

      <section className="workspace-card integrity-workspace">
        <div className={`integrity-dropzone ${dragging ? 'dragging' : ''}`} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); addFiles(event.dataTransfer.files); }}>
          <span className="integrity-drop-icon"><Hash size={25} /></span>
          <div>
            <strong>选择需要校验的文件</strong>
            <span>支持批量文件与整个文件夹，不限制单文件大小</span>
          </div>
          <div className="integrity-picker-actions">
            <button type="button" onClick={() => filesInputRef.current?.click()} disabled={busy}><FilePlus2 size={15} /> 添加文件</button>
            <button type="button" onClick={() => folderInputRef.current?.click()} disabled={busy}><FolderOpen size={15} /> 选择文件夹</button>
          </div>
          <input ref={filesInputRef} className="hidden-input" type="file" multiple onChange={(event) => addFiles(event.target.files)} />
          <input
            ref={(node) => {
              folderInputRef.current = node;
              if (node) node.setAttribute('webkitdirectory', '');
            }}
            className="hidden-input"
            type="file"
            multiple
            onChange={(event) => addFiles(event.target.files)}
          />
        </div>

        <div className="integrity-algorithms">
          <span className="integrity-algorithms-label">哈希算法</span>
          <div className="integrity-algo-chips" role="group" aria-label="选择哈希算法">
            {ALGORITHM_SPECS.map((spec) => {
              const selected = algorithms.includes(spec.id);
              return (
                <button
                  key={spec.id}
                  type="button"
                  className={`integrity-algo-chip ${selected ? 'active' : ''}`}
                  onClick={() => toggleAlgorithm(spec.id)}
                  disabled={busy}
                  aria-pressed={selected}
                  title={`${spec.id} · ${spec.bits}-bit · ${spec.note}`}
                >
                  {selected ? <Check size={11} /> : null}
                  <span>{spec.id}</span>
                  <em>{spec.bits}</em>
                </button>
              );
            })}
          </div>
          <button type="button" className="integrity-algo-bulk" onClick={toggleAllAlgorithms} disabled={busy}>
            {allSelected ? '恢复默认' : '全选'}
          </button>
        </div>

        <div className="integrity-toolbar">
          <div className="integrity-stats">
            <span><strong>{rows.length.toLocaleString()}</strong> 文件</span>
            <span><strong>{formatBytes(totalSize)}</strong> 总大小</span>
            <span title={algorithms.join('、')}><strong>{algorithms.length === 1 ? algorithms[0] : `${algorithms.length} 种`}</strong> 哈希算法</span>
          </div>
          <div className="integrity-toolbar-actions">
            <input ref={manifestInputRef} className="hidden-input" type="file" accept=".json,.txt,.md5,.sha1,.sha256,.sha512,.blake2b,.b2sum,application/json,text/plain" onChange={(event) => void loadManifest(event.target.files?.[0])} />
            <button type="button" onClick={() => manifestInputRef.current?.click()} disabled={busy}><Upload size={15} /> 导入校验清单</button>
            {manifest && <button type="button" onClick={() => { setManifest(null); setManifestName(''); }} disabled={busy}><X size={15} /> 移除清单</button>}
            <button type="button" onClick={() => setRows([])} disabled={busy || rows.length === 0}><Trash2 size={15} /> 清空</button>
          </div>
        </div>

        {manifest && (
          <div className="integrity-manifest-banner">
            <ShieldCheck size={16} />
            <div><strong>{manifestName || '完整性校验清单'}</strong><span>{manifest.files.length.toLocaleString()} 条记录 · {manifest.algorithms.length} 种算法 · 缺少 {missingCount.toLocaleString()} 个清单文件</span></div>
            <div className="integrity-manifest-counts"><span className="ok">一致 {counts.match}</span><span className="bad">不一致 {counts.mismatch}</span><span>清单外 {counts.unlisted}</span></div>
          </div>
        )}

        {busy && (
          <div className="integrity-progress">
            <div className="progress-topline"><span>{progress ? progress.concurrency > 1 ? `正在并行计算 ${algorithms.length} 种算法 · ${progress.concurrency} 路` : `正在计算 ${rows[progress.index]?.path ?? ''}` : '正在启动摘要 Worker'}</span><strong>{Math.round(ratio * 100)}%</strong></div>
            <div className="progress-track"><span style={{ width: `${ratio * 100}%` }} /></div>
            <div className="progress-meta"><span>{progress ? `${formatBytes(progress.totalProcessed)} / ${formatBytes(progress.totalBytes)}` : '准备中'}</span><span>{progress?.bytesPerSecond ? `实际 ${formatBytes(progress.bytesPerSecond)}/s` : '本地计算'}</span></div>
            <div className="integrity-performance-meta" aria-live="polite">
              <span title={progress?.backend}>
                核心 {progress?.hashBytesPerSecond ? `${formatBytes(progress.hashBytesPerSecond)}/s` : '测量中'}
              </span>
              <span>
                I/O 等待 {progress?.ioWaitRatio !== undefined ? `${Math.round(progress.ioWaitRatio * 100)}%` : '测量中'}
              </span>
              <span className="backend" title={progress?.backend}>
                {progress?.backend ?? '哈希后端初始化中'}
              </span>
            </div>
          </div>
        )}

        <div className="integrity-table-wrap">
          {rows.length === 0 ? (
            <div className="integrity-empty"><FileCheck2 size={26} /><strong>尚未添加文件</strong><span>添加文件后即可一次计算 MD5、SHA、BLAKE 等多种哈希摘要。</span></div>
          ) : (
            <div className="integrity-file-list">
              {rows.map((row, index) => {
                const status = statusFor(row);
                const hashIds = computedHashIds(row.hashes);
                return (
                  <article className={`integrity-file-row status-${status}`} key={row.id}>
                    <div className="integrity-file-index">{String(index + 1).padStart(2, '0')}</div>
                    <div className="integrity-file-main">
                      <div className="integrity-file-heading"><strong title={row.path}>{row.path}</strong><span>{formatBytes(row.file.size)}</span></div>
                      <div className="integrity-hash-area">
                        {hashIds.length > 0 && row.hashes ? (
                          hashIds.map((id) => (
                            <button
                              key={id}
                              type="button"
                              className="integrity-hash-entry"
                              onClick={() => void copyText(row.hashes![id]!, `${id} 摘要`)}
                              title={`点击复制 ${id} 摘要`}
                            >
                              <span className="integrity-hash-algo">{id}</span>
                              <code>{row.hashes?.[id]}</code>
                            </button>
                          ))
                        ) : (
                          <span className="integrity-hash-pending">{status === 'hashing' ? `正在计算 ${algorithms.length} 种摘要…` : status === 'error' ? row.error : '等待计算'}</span>
                        )}
                      </div>
                    </div>
                    <span className={`integrity-status status-${status}`}>
                      {status === 'match' ? <><Check size={13} /> 一致</> : status === 'mismatch' ? <><X size={13} /> 不一致</> : status === 'unlisted' ? '清单外' : status === 'ready' ? '已计算' : status === 'hashing' ? <><RefreshCw className="spin" size={13} /> 计算中</> : status === 'error' ? '错误' : '未计算'}
                    </span>
                    <div className="integrity-row-actions">
                      {hashIds.length > 0 && <button type="button" onClick={() => copyRowHashes(row)} aria-label={`复制 ${row.path} 摘要`}><Copy size={15} /></button>}
                      <button type="button" onClick={() => removeRow(row.id)} disabled={busy} aria-label={`移除 ${row.path}`}><X size={15} /></button>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </div>

        <div className="integrity-actions">
          {busy ? (
            <button type="button" className="integrity-cancel" onClick={cancelHashing} disabled={cancelling}><X size={16} /> {cancelling ? '正在取消…' : '取消计算'}</button>
          ) : (
            <button type="button" className="integrity-primary" onClick={startHashing} disabled={rows.length === 0 || algorithms.length === 0}><Hash size={17} /> {manifest ? '开始批量校验' : '计算全部摘要'}</button>
          )}
          <button type="button" onClick={copyChecksums} disabled={busy || !rows.some((row) => computedHashIds(row.hashes).length > 0)}><Clipboard size={15} /> 复制摘要</button>
          <button type="button" onClick={exportManifest} disabled={busy || !rows.some((row) => computedHashIds(row.hashes).length > 0)}><Download size={15} /> 导出清单</button>
        </div>
      </section>
    </>
  );
}
