import { BadgeCheck, Maximize2, Palette, ScanSearch, Shapes, ShieldCheck, X } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { safetyBadgeDataUrl } from './safetyBadgeVisual';
import { useFocusTrap } from './useFocusTrap';

interface SafetyBadgeProps {
  seed: string;
  pskProtected: boolean;
  /** 我方是否已确认徽章一致 / Whether we have confirmed the badge */
  selfVerified: boolean;
  /** 对方是否已确认徽章一致 / Whether the peer has confirmed the badge */
  peerVerified: boolean;
  /** 用户点击「两端一致」时回调：由父组件标记我方已确认并通知对方 / Called when the user confirms the badges match */
  onConfirm: () => void;
  /** 递增即请求打开弹窗（锁定提示条等外部入口使用）/ Bump to open the dialog from outside (locked-notice button) */
  openTick: number;
}

export default function SafetyBadge({ seed, pskProtected, selfVerified, peerVerified, onConfirm, openTick }: SafetyBadgeProps) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const titleId = useId();
  const bothVerified = selfVerified && peerVerified;
  useFocusTrap(dialogRef, open);
  const compactIcon = useMemo(() => safetyBadgeDataUrl(seed, 72), [seed]);
  const largeIcon = useMemo(() => safetyBadgeDataUrl(seed, 240), [seed]);

  // 每次会话重建（新徽章）都强制弹出比对，直到我方确认；重协商同样重新锁定。
  // Every session (re)negotiation force-opens the comparison until we confirm; a rekey re-locks.
  const autoOpenedForRef = useRef<string | null>(null);
  useEffect(() => {
    if (selfVerified || autoOpenedForRef.current === seed) return;
    autoOpenedForRef.current = seed;
    setOpen(true);
  }, [seed, selfVerified]);

  // 外部入口请求打开弹窗 / External requests to open the dialog
  useEffect(() => {
    if (openTick > 0) setOpen(true);
  }, [openTick]);

  useEffect(() => {
    if (!open) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    closeRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = previousOverflow;
      triggerRef.current?.focus();
    };
  }, [open]);

  const dialog = open ? createPortal(
    <div className="safety-badge-overlay" role="presentation" onPointerDown={() => setOpen(false)}>
      <section
        ref={dialogRef}
        className="safety-badge-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onPointerDown={(event) => event.stopPropagation()}
      >
        <button ref={closeRef} type="button" className="safety-badge-close" onClick={() => setOpen(false)} aria-label="关闭视觉安全徽章">
          <X size={18} />
        </button>

        <div className="safety-badge-dialog-heading">
          <span><ShieldCheck size={18} /></span>
          <div>
            <strong id={titleId}>视觉安全徽章</strong>
            <small>{pskProtected ? 'PSK + X25519 会话指纹' : '仅 X25519 · 必须人工核验'}</small>
          </div>
        </div>

        <div className="safety-badge-stage">
          <div className="safety-badge-halo" aria-hidden="true" />
          <img src={largeIcon} alt="当前会话的视觉安全徽章" width={240} height={240} draggable={false} />
        </div>

        <div className="safety-badge-instruction">
          <strong>请确认双方徽章完全一致</strong>
          <p>通过通话、面对面或另一条可信渠道，比对颜色、外部轮廓与内部几何切面。双方确认一致后对话才会解锁。</p>
        </div>

        <div className="safety-badge-checkpoints" aria-label="需要比对的视觉特征">
          <span><Palette size={15} /> 颜色</span>
          <span><Shapes size={15} /> 轮廓</span>
          <span><ScanSearch size={15} /> 切面</span>
        </div>

        <div className={`safety-badge-peer ${peerVerified ? 'ok' : ''}`} role="status">
          <BadgeCheck size={14} />
          {peerVerified ? '对方已确认徽章一致' : '对方尚未确认'}
        </div>

        <div className="safety-badge-privacy">
          <ShieldCheck size={14} /> 图形由本次会话密钥在本地派生，不会上传；重新协商后会自动变化。
        </div>

        <button
          type="button"
          className="safety-badge-confirm"
          disabled={selfVerified}
          onClick={() => {
            onConfirm();
            setOpen(false);
          }}
        >
          <BadgeCheck size={17} /> {selfVerified ? '已确认一致' : '两端一致，完成核验'}
        </button>
      </section>
    </div>,
    document.body,
  ) : null;

  const triggerLabel = bothVerified
    ? '徽章已核验'
    : selfVerified
      ? '等待对方确认'
      : '视觉安全徽章';
  const triggerHint = bothVerified
    ? '双方已确认一致'
    : selfVerified
      ? '对方确认后解锁对话'
      : '对话前必须比对';

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className={`chat-safety-badge ${bothVerified ? 'verified' : 'unverified'}`}
        onClick={() => setOpen(true)}
        aria-haspopup="dialog"
        aria-expanded={open}
        title="点击放大并与对方比对视觉安全徽章"
      >
        <span className="chat-safety-badge-icon">
          <img src={compactIcon} alt="" width={32} height={32} draggable={false} />
        </span>
        <span className="chat-safety-badge-copy">
          <strong>{triggerLabel}</strong>
          <small>{triggerHint}</small>
        </span>
        {bothVerified ? <BadgeCheck className="chat-safety-badge-state" size={16} /> : <Maximize2 className="chat-safety-badge-state" size={14} />}
      </button>
      {dialog}
    </>
  );
}
