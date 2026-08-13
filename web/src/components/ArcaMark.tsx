export function ArcaMark({ size = 36 }: { size?: number }) {
  return (
    <svg
      aria-hidden="true"
      className="arca-mark"
      height={size}
      viewBox="0 0 48 48"
      width={size}
    >
      <path d="M7 41V23C7 13.6 14.6 6 24 6s17 7.6 17 17v18h-9V23a8 8 0 0 0-16 0v18H7Z" />
      <path className="arca-mark-cut" d="M20 41V28a4 4 0 0 1 8 0v13h-8Z" />
    </svg>
  );
}
