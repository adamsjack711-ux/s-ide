/** Line-icon set matching the design (24×24, stroke currentColor, 1.7). */
type El = [string, Record<string, unknown>];

const P: Record<string, El[]> = {
  grid: [["rect", { x: 3, y: 3, width: 7, height: 7, rx: 1.5 }], ["rect", { x: 14, y: 3, width: 7, height: 7, rx: 1.5 }], ["rect", { x: 14, y: 14, width: 7, height: 7, rx: 1.5 }], ["rect", { x: 3, y: 14, width: 7, height: 7, rx: 1.5 }]],
  code: [["polyline", { points: "16 18 22 12 16 6" }], ["polyline", { points: "8 6 2 12 8 18" }]],
  filter: [["polygon", { points: "21 4 3 4 10 12.4 10 19 14 21 14 12.4 21 4" }]],
  search: [["circle", { cx: 11, cy: 11, r: 7 }], ["line", { x1: 21, y1: 21, x2: 16.65, y2: 16.65 }]],
  share: [["circle", { cx: 18, cy: 5, r: 2.6 }], ["circle", { cx: 6, cy: 12, r: 2.6 }], ["circle", { cx: 18, cy: 19, r: 2.6 }], ["line", { x1: 8.2, y1: 13.3, x2: 15.8, y2: 17.7 }], ["line", { x1: 15.8, y1: 6.3, x2: 8.2, y2: 10.7 }]],
  terminal: [["polyline", { points: "4 17 10 11 4 5" }], ["line", { x1: 12, y1: 19, x2: 20, y2: 19 }]],
  sliders: [["line", { x1: 4, y1: 21, x2: 4, y2: 14 }], ["line", { x1: 4, y1: 10, x2: 4, y2: 3 }], ["line", { x1: 12, y1: 21, x2: 12, y2: 12 }], ["line", { x1: 12, y1: 8, x2: 12, y2: 3 }], ["line", { x1: 20, y1: 21, x2: 20, y2: 16 }], ["line", { x1: 20, y1: 12, x2: 20, y2: 3 }], ["circle", { cx: 4, cy: 12, r: 2 }], ["circle", { cx: 12, cy: 10, r: 2 }], ["circle", { cx: 20, cy: 14, r: 2 }]],
  sparkle: [["path", { d: "M12 3 L13.5 9.2 L20 11 L13.5 12.8 L12 19 L10.5 12.8 L4 11 L10.5 9.2 Z" }]],
  shield: [["path", { d: "M12 3 L20 6 V11 C20 16 16.5 19.5 12 21 C7.5 19.5 4 16 4 11 V6 Z" }]],
  target: [["circle", { cx: 12, cy: 12, r: 8 }], ["line", { x1: 12, y1: 1, x2: 12, y2: 4 }], ["line", { x1: 12, y1: 20, x2: 12, y2: 23 }], ["line", { x1: 1, y1: 12, x2: 4, y2: 12 }], ["line", { x1: 20, y1: 12, x2: 23, y2: 12 }], ["circle", { cx: 12, cy: 12, r: 1.6 }]],
  chart: [["line", { x1: 3, y1: 21, x2: 21, y2: 21 }], ["rect", { x: 4, y: 12, width: 3.6, height: 8, rx: 1 }], ["rect", { x: 10.2, y: 7, width: 3.6, height: 13, rx: 1 }], ["rect", { x: 16.4, y: 3, width: 3.6, height: 17, rx: 1 }]],
  book: [["path", { d: "M4 5 a2 2 0 0 1 2-2 h13 v16 H6 a2 2 0 0 0-2 2 Z" }], ["line", { x1: 4, y1: 19, x2: 19, y2: 19 }]],
  gear: [["circle", { cx: 12, cy: 12, r: 3 }], ["path", { d: "M19.4 13a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2V21a2 2 0 0 1-4 0v-.2a1.7 1.7 0 0 0-2.9-1.2l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.7 1.7 0 0 0 4.6 13H4a2 2 0 0 1 0-4h.2a1.7 1.7 0 0 0 1.2-2.9l-.1-.1A2 2 0 1 1 8.1 3.2l.1.1A1.7 1.7 0 0 0 11 4.6V4a2 2 0 0 1 4 0v.2a1.7 1.7 0 0 0 2.9 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1A1.7 1.7 0 0 0 19.4 11H20a2 2 0 0 1 0 4Z" }]],
  box: [["path", { d: "M3 7 L12 2 L21 7 V17 L12 22 L3 17 Z" }], ["line", { x1: 3, y1: 7, x2: 12, y2: 12 }], ["line", { x1: 21, y1: 7, x2: 12, y2: 12 }], ["line", { x1: 12, y1: 12, x2: 12, y2: 22 }]],
  "chevron-down": [["polyline", { points: "6 9 12 15 18 9" }]],
};

export default function Icon({ name, size = 20 }: { name: keyof typeof P | string; size?: number }) {
  const els = P[name] ?? [];
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      {els.map(([tag, attrs], i) => {
        const Tag = tag as any;
        return <Tag key={i} {...attrs} />;
      })}
    </svg>
  );
}
