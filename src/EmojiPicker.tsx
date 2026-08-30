/**
 * 轻量自包含表情面板：精选分组 + 最近使用。
 * Lightweight self-contained emoji picker: curated groups + recents.
 * 不引入第三方 emoji 数据库（需从 CDN 拉取 ~1MB）；私密工具坚持零外部请求，精选集硬编码进 bundle（约 2KB）。
 * No third-party emoji DB (~1MB CDN fetch); zero external requests, curated set hardcoded (~2KB).
 */
import { useEffect, useRef, useState } from 'react';

const GROUPS: Array<{ id: string; label: string; emojis: string[] }> = [
  {
    id: 'smileys',
    label: '表情',
    emojis: ['😀', '😁', '😂', '🤣', '😊', '😇', '🙂', '😉', '😍', '🥰', '😘', '😜', '🤪', '🤨', '🧐', '🤓', '😎', '🥳', '😏', '😒', '😞', '😔', '😢', '😭', '😤', '😠', '🤯', '😱', '🥶', '🤔', '🤫', '🤝'],
  },
  {
    id: 'gestures',
    label: '手势',
    emojis: ['👍', '👎', '👌', '🤌', '✌️', '🤞', '🫶', '🤟', '🤘', '👏', '🙌', '🫡', '🤲', '🙏', '💪', '🫰', '☝️', '👆', '👇', '👋', '🤚', '✋', '🖖', '🤙', '✍️', '💅', '👀', '🧠', '🫵', '🫱', '🫲', '👄'],
  },
  {
    id: 'animals',
    label: '动物',
    emojis: ['🐱', '🐶', '🦊', '🐻', '🐼', '🐨', '🐯', '🦁', '🐮', '🐷', '🐸', '🐵', '🐔', '🐧', '🐦', '🦉', '🦇', '🐺', '🐗', '🐴', '🦄', '🐝', '🦋', '🐢', '🐍', '🐙', '🦑', '🦀', '🐳', '🐬', '🦈', '🐊'],
  },
  {
    id: 'food',
    label: '食物',
    emojis: ['🍏', '🍎', '🍐', '🍊', '🍋', '🍌', '🍉', '🍇', '🍓', '🫐', '🍒', '🍑', '🥭', '🍍', '🥥', '🥝', '🍅', '🥑', '🌶️', '🌽', '🥕', '🍞', '🥐', '🧀', '🍚', '🍜', '🍣', '🍱', '🍰', '🎂', '🍫', '🍩'],
  },
  {
    id: 'activity',
    label: '活动',
    emojis: ['⚽', '🏀', '🏈', '⚾', '🎾', '🏐', '🏓', '🏸', '🥊', '🎯', '🎮', '🎲', '🧩', '🎭', '🎨', '🎬', '🎤', '🎧', '🎵', '🎹', '🎸', '🎻', '🥁', '🏆', '🥇', '🎖️', '🏒', '⛷️', '🚴', '🏊', '🧗', '🏸'],
  },
  {
    id: 'objects',
    label: '物品',
    emojis: ['💻', '🖥️', '⌨️', '🖱️', '💾', '💿', '📀', '📱', '☎️', '📟', '📠', '🔋', '🔌', '💡', '🔦', '🕯️', '🧲', '🔍', '🔒', '🔑', '🛠️', '⚙️', '🧪', '🔬', '📡', '✈️', '🚀', '🛸', '🚗', '🗿', '⏰', '💣'],
  },
  {
    id: 'symbols',
    label: '符号',
    emojis: ['❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '💯', '🔥', '✨', '⚡', '❄️', '🌈', '☀️', '🌙', '⭐', '🌟', '💎', '🔔', '📍', '✅', '❌', '❗', '❓', '💤', '🎉', '🎁', '🆔', '🔞', '🔴', '🟢'],
  },
];

const RECENT_KEY = 'crypto-chat-recent-emoji';
const RECENT_MAX = 16;

function loadRecent(): string[] {
  try {
    const raw = JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]') as unknown;
    return Array.isArray(raw) ? raw.filter((e): e is string => typeof e === 'string').slice(0, RECENT_MAX) : [];
  } catch {
    return [];
  }
}

function saveRecent(emoji: string): string[] {
  const next = [emoji, ...loadRecent().filter((e) => e !== emoji)].slice(0, RECENT_MAX);
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(next));
  } catch {
    /* 隐私模式下忽略 / Ignored in private mode */
  }
  return next;
}

export default function EmojiPicker({
  onPick,
  onClose,
}: {
  onPick: (emoji: string) => void;
  onClose: () => void;
}) {
  const [recent, setRecent] = useState<string[]>(loadRecent);
  const [group, setGroup] = useState<string>(GROUPS[0].id);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDocPointer = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) onClose();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('pointerdown', onDocPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onDocPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [onClose]);

  const active = GROUPS.find((g) => g.id === group) ?? GROUPS[0];

  const pick = (emoji: string) => {
    setRecent(saveRecent(emoji));
    onPick(emoji);
  };

  return (
    <div className="emoji-pop" ref={rootRef} role="dialog" aria-label="表情选择">
      {recent.length > 0 && (
        <>
          <div className="emoji-group-label">最近</div>
          <div className="emoji-grid emoji-recent">
            {recent.map((emoji) => (
              <button key={`r-${emoji}`} type="button" onClick={() => pick(emoji)}>{emoji}</button>
            ))}
          </div>
        </>
      )}
      <div className="emoji-tabs" role="tablist">
        {GROUPS.map((g) => (
          <button
            key={g.id}
            type="button"
            role="tab"
            aria-selected={g.id === group}
            className={g.id === group ? 'active' : ''}
            onClick={() => setGroup(g.id)}
          >
            {g.label}
          </button>
        ))}
      </div>
      <div className="emoji-grid">
        {active.emojis.map((emoji) => (
          <button key={emoji} type="button" onClick={() => pick(emoji)}>{emoji}</button>
        ))}
      </div>
    </div>
  );
}
