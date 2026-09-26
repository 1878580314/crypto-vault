/**
 * 极简焦点圈禁：模态层打开期间把 Tab / Shift+Tab 限制在容器内，Esc 与焦点恢复由调用方处理。
 * Minimal focus trap: while a modal layer is open, Tab / Shift+Tab stay inside the container;
 * Escape handling and focus restoration remain the caller's job.
 */
import { useEffect, type RefObject } from 'react';

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'textarea:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

export function useFocusTrap(containerRef: RefObject<HTMLElement | null>, active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const container = containerRef.current;
    if (!container) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Tab') return;
      // fixed 定位元素的 offsetParent 为 null，不能用其判断可见性 / offsetParent is null for
      // fixed-positioned nodes, so visibility is checked via getClientRects instead.
      const items = Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE))
        .filter((el) => el.getClientRects().length > 0);
      if (items.length === 0) {
        event.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const current = document.activeElement;
      if (event.shiftKey) {
        if (!(current instanceof HTMLElement) || !container.contains(current) || current === first) {
          event.preventDefault();
          last.focus();
        }
      } else if (!(current instanceof HTMLElement) || !container.contains(current) || current === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, [containerRef, active]);
}
