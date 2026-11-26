interface SparklineProps {
  data: number[];
  label: string;
  value: string;
  /** CSS color (defaults to the accent token). */
  color?: string;
}

/** Tiny dependency-free area+line chart that scales to the data range. */
export function Sparkline({ data, label, value, color = "var(--c-accent)" }: SparklineProps) {
  const w = 240, h = 44;
  const n = data.length;
  const max = Math.max(1, ...data);
  const min = Math.min(0, ...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = n <= 1 ? 0 : (i / (n - 1)) * w;
    const y = h - ((v - min) / range) * (h - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const line = pts.join(" ");

  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-xs text-ink-soft">{label}</span>
        <b className="text-sm tabular-nums text-accent-d">{value}</b>
      </div>
      <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="h-11 w-full">
        {n > 1 ? (
          <>
            <polygon points={`0,${h} ${line} ${w},${h}`} fill={color} opacity={0.12} />
            <polyline points={line} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
          </>
        ) : (
          <text x={4} y={h / 2 + 3} fontSize={10} className="fill-muted">сбор данных…</text>
        )}
      </svg>
    </div>
  );
}
