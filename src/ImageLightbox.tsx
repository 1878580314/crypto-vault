import { X } from 'lucide-react';
import { useEffect, useId, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useFocusTrap } from './useFocusTrap';

interface ImageLightboxProps {
  url: string;
  name: string;
  onClose: () => void;
}

export default function ImageLightbox({ url, name, onClose }: ImageLightboxProps) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const titleId = useId();
  useFocusTrap(dialogRef, true);

  useEffect(() => {
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    closeRef.current?.focus({ preventScroll: true });

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = previousOverflow;
      if (previousFocusRef.current?.isConnected) previousFocusRef.current.focus({ preventScroll: true });
    };
  }, [onClose]);

  return createPortal(
    <div className="chat-image-lightbox-overlay" role="presentation" onPointerDown={onClose}>
      <section
        ref={dialogRef}
        className="chat-image-lightbox-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onPointerDown={(event) => event.stopPropagation()}
      >
        <button ref={closeRef} type="button" className="chat-image-lightbox-close" onClick={onClose} aria-label="关闭图片预览">
          <X size={20} />
        </button>
        <div className="chat-image-lightbox-stage">
          <img src={url} alt={name} draggable={false} />
        </div>
        <div id={titleId} className="chat-image-lightbox-name" title={name}>{name}</div>
      </section>
    </div>,
    document.body,
  );
}
