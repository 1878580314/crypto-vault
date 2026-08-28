import { BadgeCheck, Maximize2, Palette, ScanSearch, Shapes, ShieldCheck, X } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { safetyBadgeDataUrl } from './safetyBadgeVisual';

interface SafetyBadgeProps {
  seed: string;
  pskProtected: boolean;
}

export default function SafetyBadge({ seed, pskProtected }: SafetyBadgeProps) {
  const [open, setOpen] = useState(false);
  const [verified, setVerified] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const compactIcon = useMemo(() => safetyBadgeDataUrl(seed, 72), [seed]);
  const largeIcon = useMemo(() => safetyBadgeDataUrl(seed, 240), [seed]);

  useEffect(() => {
    setVerified(false);
    setOpen(false);
  }, [seed]);

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
          <p>通过通话、面对面或另一条可信渠道，比对颜色、外部轮廓与内部几何切面。</p>
        </div>

        <div className="safety-badge-checkpoints" aria-label="需要比对的视觉特征">
          <span><Palette size={15} /> 颜色</span>
          <span><Shapes size={15} /> 轮廓</span>
          <span><ScanSearch size={15} /> 切面</span>
        </div>

        <div className="safety-badge-privacy">
          <ShieldCheck size={14} /> 图形由本次会话密钥在本地派生，不会上传；重新协商后会自动变化。
        </div>

        <button
          type="button"
          className="safety-badge-confirm"
          onClick={() => {
            setVerified(true);
            setOpen(false);
          }}
        >
          <BadgeCheck size={17} /> 两端一致，完成核验
        </button>
      </section>
    </div>,
    document.body,
  ) : null;

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className={`chat-safety-badge ${verified ? 'verified' : ''}`}
        onClick={() => setOpen(true)}
        aria-haspopup="dialog"
        aria-expanded={open}
        title="点击放大并与对方比对视觉安全徽章"
      >
        <span className="chat-safety-badge-icon">
          <img src={compactIcon} alt="" width={32} height={32} draggable={false} />
        </span>
        <span className="chat-safety-badge-copy">
          <strong>{verified ? '徽章已核验' : '视觉安全徽章'}</strong>
          <small>{verified ? '当前会话一致' : '点击与对方比对'}</small>
        </span>
        {verified ? <BadgeCheck className="chat-safety-badge-state" size={16} /> : <Maximize2 className="chat-safety-badge-state" size={14} />}
      </button>
      {dialog}
    </>
  );
}
