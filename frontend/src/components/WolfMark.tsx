export function WolfMark({ className = "h-9 w-9" }: { className?: string }) {
  // Original geometric wolf-head-in-shield mark for WOLVE AI.
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden="true">
      <defs>
        <linearGradient id="wg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#2563eb" />
          <stop offset="1" stopColor="#1e3a8a" />
        </linearGradient>
      </defs>
      <path d="M32 3 56 12v18c0 15-10.5 26.5-24 31C18.5 56.5 8 45 8 30V12Z" fill="#ffffff" stroke="url(#wg)" strokeWidth="2.5" />
      <path d="M18 18 25 29 32 25 39 29 46 18 44 36 38 44 32 50 26 44 20 36Z" fill="url(#wg)" opacity="0.95" />
      <path d="M25 33 29.5 35 25.5 36.5Z M39 33 34.5 35 38.5 36.5Z" fill="#ffffff" />
      <path d="M29 43 32 46 35 43 32 41.5Z" fill="#ffffff" />
    </svg>
  );
}
