export function BeeMark({ className = "h-9 w-9" }: { className?: string }) {
  // Original Three Bees (3B) mark: a honeycomb hexagon holding three cells.
  const cell = (cx: number, cy: number, r: number) =>
    Array.from({ length: 6 }, (_, i) => {
      const a = (Math.PI / 3) * i - Math.PI / 2;
      return `${(cx + r * Math.cos(a)).toFixed(2)},${(cy + r * Math.sin(a)).toFixed(2)}`;
    }).join(" ");
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden="true">
      <defs>
        <linearGradient id="bm-honey" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#fbbf24" />
          <stop offset="1" stopColor="#d97706" />
        </linearGradient>
      </defs>
      <polygon points={cell(32, 32, 30)} fill="#1e293b" stroke="url(#bm-honey)" strokeWidth="2.5" strokeLinejoin="round" />
      <polygon points={cell(32, 21.5, 9)} fill="url(#bm-honey)" />
      <polygon points={cell(22.9, 37.2, 9)} fill="url(#bm-honey)" />
      <polygon points={cell(41.1, 37.2, 9)} fill="url(#bm-honey)" />
    </svg>
  );
}
