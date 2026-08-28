import { toSvg, type JdenticonConfig } from 'jdenticon/browser';

const BADGE_CONFIG: JdenticonConfig = {
  hues: [8, 34, 148, 178, 202, 224, 248, 274, 302, 330],
  lightness: {
    color: [0.46, 0.72],
    grayscale: [0.68, 0.88],
  },
  saturation: {
    color: 0.72,
    grayscale: 0.22,
  },
  padding: 0.07,
  backColor: '#0000',
};

export function safetyBadgeSvg(seed: string, size: number): string {
  return toSvg(seed, size, BADGE_CONFIG);
}

export function safetyBadgeDataUrl(seed: string, size: number): string {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(safetyBadgeSvg(seed, size))}`;
}
