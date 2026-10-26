/** Titled card built on the shared noc-panel classes. */

import { useId, type ReactNode } from "react";

export interface PanelProps {
  title: string;
  /** Icon rendered before the title. */
  icon?: ReactNode;
  /** Content aligned to the right of the header (scope chips, legends, buttons). */
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}

export function Panel({ title, icon, actions, children, className = "" }: PanelProps) {
  const titleId = useId();
  return (
    <section aria-labelledby={titleId} className={`noc-panel flex min-w-0 flex-col ${className}`}>
      <header className="noc-panel-header">
        <h2 id={titleId} className="noc-title min-w-0">
          {icon}
          <span className="truncate">{title}</span>
        </h2>
        {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
      </header>
      <div className="min-w-0 flex-1 p-4">{children}</div>
    </section>
  );
}
