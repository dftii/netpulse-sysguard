/** Small coloured status indicator with an optional radar-style pulse. */

export type StatusDotSize = "sm" | "md" | "lg";

const SIZE_CLASSES: Record<StatusDotSize, string> = {
  sm: "size-1.5",
  md: "size-2",
  lg: "size-2.5",
};

export interface StatusDotProps {
  /** Tailwind background class that sets the colour, e.g. "bg-emerald-400". */
  colorClass: string;
  /** Emit a soft expanding ring to signal a live or alerting state. */
  pulse?: boolean;
  size?: StatusDotSize;
}

export function StatusDot({ colorClass, pulse = false, size = "md" }: StatusDotProps) {
  const sizeClass = SIZE_CLASSES[size];
  return (
    <span className={`relative inline-flex shrink-0 ${sizeClass}`} aria-hidden="true">
      {pulse ? (
        <span className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-60 ${colorClass}`} />
      ) : null}
      <span className={`relative inline-flex rounded-full ${sizeClass} ${colorClass}`} />
    </span>
  );
}
