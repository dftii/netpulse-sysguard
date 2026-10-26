/** Responsive grid of node cards with single-selection focus. */

import { Radar, Server, X } from "lucide-react";
import { useId } from "react";
import type { NodeTelemetry } from "../../types/api";
import type { NodeHistoryPoint } from "../../types/dashboard";
import { NodeCard } from "./NodeCard";

export interface ServerGridProps {
  nodes: NodeTelemetry[];
  /** Rolling history keyed by node_id. */
  history: Record<number, NodeHistoryPoint[]>;
  selectedNodeId: number | null;
  /** Called with the node id to select it, or null to clear the selection. */
  onSelect: (nodeId: number | null) => void;
}

export function ServerGrid({ nodes, history, selectedNodeId, onSelect }: ServerGridProps) {
  const headingId = useId();
  const selectedNode = selectedNodeId === null ? null : nodes.find((n) => n.node_id === selectedNodeId);

  return (
    <section aria-labelledby={headingId}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 id={headingId} className="noc-title">
          <Server className="size-4 text-noc-accent" aria-hidden="true" />
          Infrastructure nodes
          <span className="rounded bg-slate-800/80 px-1.5 py-0.5 font-mono text-[10px] tracking-normal text-slate-400">
            {nodes.length}
          </span>
        </h2>
        {selectedNode ? (
          <button type="button" className="noc-button" onClick={() => onSelect(null)}>
            <X className="size-3.5" aria-hidden="true" />
            Clear focus: {selectedNode.display_name}
          </button>
        ) : (
          <p className="text-[11px] text-noc-muted">Select a node to focus the charts on it</p>
        )}
      </div>

      {nodes.length === 0 ? (
        <div className="noc-panel flex flex-col items-center gap-3 px-6 py-12 text-center">
          <Radar className="size-8 animate-pulse text-noc-accent/70" aria-hidden="true" />
          <p className="font-mono text-xs text-slate-400">Waiting for the first telemetry frame…</p>
        </div>
      ) : (
        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {nodes.map((node) => (
            <li key={node.node_id} className="min-w-0">
              <NodeCard
                node={node}
                history={history[node.node_id]}
                selected={node.node_id === selectedNodeId}
                onSelect={onSelect}
              />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
