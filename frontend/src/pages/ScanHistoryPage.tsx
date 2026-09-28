/**
 * Scan History — all scan runs, metrics, and ability to start new scans.
 */

import React, { useState, useMemo } from 'react';
import {
  Play, Clock, CheckCircle2, XCircle, Loader2,
  BarChart2, FlaskConical, GitBranch, ChevronDown, ChevronUp,
} from 'lucide-react';
import type { ScanRun } from '../types';

// ── Status helpers ─────────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  running: { label: 'Running', color: '#38bdf8', icon: <Loader2 size={13} className="spin" /> },
  done:    { label: 'Done',    color: '#34d399', icon: <CheckCircle2 size={13} /> },
  error:   { label: 'Error',   color: '#f87171', icon: <XCircle size={13} /> },
  queued:  { label: 'Queued',  color: '#fbbf24', icon: <Clock size={13} /> },
};

function duration(run: ScanRun) {
  if (run.metrics?.durationSeconds) return `${run.metrics.durationSeconds.toFixed(1)}s`;
  if (run.finishedAt) return `${((run.finishedAt - run.startedAt) / 1000).toFixed(1)}s`;
  if (run.status === 'running') return 'Running…';
  return '—';
}

// ── Row ────────────────────────────────────────────────────────────────────────

function RunRow({ run }: { run: ScanRun }) {
  const [expanded, setExpanded] = useState(false);
  const { label, color, icon } = STATUS_CONFIG[run.status] || STATUS_CONFIG.done;

  return (
    <>
      <tr className="scan-run-row" onClick={() => setExpanded(v => !v)}>
        <td>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#64748b', fontSize: 12 }}>
            {run.type === 'repo'
              ? <><GitBranch size={13} style={{ color: '#a78bfa' }} />{run.repository?.split('/').pop() || 'Repository'}</>
              : <><FlaskConical size={13} style={{ color: '#38bdf8' }} />Sandbox</>}
          </div>
        </td>
        <td><span style={{ fontFamily: 'JetBrains Mono, monospace', color: '#475569', fontSize: 11 }}>#{run.id.slice(-8)}</span></td>
        <td>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color, background: `${color}15`, border: `1px solid ${color}44`, borderRadius: 20, padding: '2px 8px', fontSize: 11, fontWeight: 600 }}>
            {icon} {label}
          </span>
        </td>
        <td><span style={{ color: '#64748b', fontSize: 12 }}>{new Date(run.startedAt).toLocaleString()}</span></td>
        <td><span style={{ color: '#64748b', fontSize: 12 }}>{duration(run)}</span></td>
        <td><span style={{ color: '#fb923c', fontSize: 13, fontWeight: 600 }}>{run.confirmedCount}</span></td>
        <td><span style={{ color: '#64748b', fontSize: 13 }}>{run.fpCount}</span></td>
        <td><span style={{ color: '#64748b', fontSize: 12 }}>{run.metrics?.tokensEstimated ? `${(run.metrics.tokensEstimated / 1000).toFixed(1)}k` : '—'}</span></td>
        <td>
          {expanded ? <ChevronUp size={14} style={{ color: '#475569' }} /> : <ChevronDown size={14} style={{ color: '#475569' }} />}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={9} style={{ padding: 0, background: 'rgba(255,255,255,0.015)', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
            <div style={{ padding: '16px 20px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 10 }}>
                {[
                  ['Repository', run.repository || '—'],
                  ['Type', run.type],
                  ['Discovery Model', run.model],
                  ['Challenger Model', run.challengerModel],
                  ['Workers', run.workers],
                  ['Challengers', run.challengers],
                  ['SAST Findings', run.metrics?.sastFindingCount ?? '—'],
                  ['FP Reduction', run.metrics?.fpReductionRate ? `${run.metrics.fpReductionRate.toFixed(1)}%` : '—'],
                  ['Precision', run.metrics?.precisionPct ? `${run.metrics.precisionPct.toFixed(1)}%` : '—'],
                  ['Recall', run.metrics?.recallPct ? `${run.metrics.recallPct.toFixed(1)}%` : '—'],
                  ['F1', run.metrics?.f1 ? run.metrics.f1.toFixed(3) : '—'],
                  ['Delta vs SAST', run.metrics?.deltaVsSast ?? '—'],
                ].map(([k, v]) => (
                  <div key={String(k)} style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 6, padding: '8px 10px' }}>
                    <div style={{ fontSize: 10, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{k}</div>
                    <div style={{ fontSize: 13, color: '#94a3b8', marginTop: 3 }}>{String(v)}</div>
                  </div>
                ))}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Main ───────────────────────────────────────────────────────────────────────

interface ScanHistoryPageProps {
  scanRuns: ScanRun[];
  onNavigate: (page: string) => void;
}

export default function ScanHistoryPage({ scanRuns, onNavigate }: ScanHistoryPageProps) {
  const [typeFilter, setTypeFilter] = useState<'all' | 'sandbox' | 'repo'>('all');

  const sorted = useMemo(() =>
    [...scanRuns]
      .filter(r => typeFilter === 'all' || r.type === typeFilter)
      .sort((a, b) => b.startedAt - a.startedAt),
    [scanRuns, typeFilter]
  );

  // Aggregate metrics
  const totalConfirmed = scanRuns.reduce((a, r) => a + r.confirmedCount, 0);
  const totalFP = scanRuns.reduce((a, r) => a + r.fpCount, 0);
  const avgFpReduction = scanRuns.filter(r => r.metrics?.fpReductionRate != null).reduce((a, r, _, arr) => a + (r.metrics!.fpReductionRate / arr.length), 0);

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Scan History</h1>
          <p className="page-subtitle">{scanRuns.length} total scans across all repositories</p>
        </div>
        <button className="btn-primary" onClick={() => onNavigate('scan')}>
          <Play size={14} /> New Scan
        </button>
      </div>

      {/* Aggregate summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 24 }}>
        {[
          { label: 'Total Scans', value: scanRuns.length, accent: '#38bdf8', icon: <BarChart2 size={18} /> },
          { label: 'Total Confirmed', value: totalConfirmed, accent: '#fb923c', icon: <CheckCircle2 size={18} /> },
          { label: 'FP Eliminated', value: totalFP, accent: '#a78bfa', icon: <XCircle size={18} /> },
          { label: 'Avg FP Reduction', value: scanRuns.filter(r => r.metrics?.fpReductionRate != null).length > 0 ? `${avgFpReduction.toFixed(1)}%` : '—', accent: '#34d399', icon: <BarChart2 size={18} /> },
        ].map(({ label, value, accent, icon }) => (
          <div key={label} style={{ background: 'rgba(13,23,38,0.7)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ background: `${accent}15`, color: accent, borderRadius: 10, padding: 10, display: 'flex' }}>{icon}</div>
            <div>
              <div style={{ color: '#475569', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
              <div style={{ color: accent, fontSize: 22, fontWeight: 700, marginTop: 2 }}>{value}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Filter tabs */}
      <div style={{ display: 'flex', gap: 2, marginBottom: 16, background: 'rgba(255,255,255,0.03)', borderRadius: 8, padding: 3, width: 'fit-content' }}>
        {(['all', 'repo', 'sandbox'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTypeFilter(t)}
            style={{
              padding: '5px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer', transition: 'all 0.15s',
              background: typeFilter === t ? 'rgba(255,255,255,0.08)' : 'transparent',
              border: 'none',
              color: typeFilter === t ? '#e2e8f0' : '#475569',
            }}
          >
            {t === 'all' ? 'All' : t === 'repo' ? '⬡ Repo Scans' : '◈ Sandbox'}
          </button>
        ))}
      </div>

      {/* Table */}
      {sorted.length === 0 ? (
        <div className="empty-full">
          <Play size={36} style={{ color: '#1e293b' }} />
          <p style={{ color: '#475569', marginTop: 12, fontSize: 14 }}>No scan runs yet. <button className="link-btn" onClick={() => onNavigate('scan')}>Start your first scan →</button></p>
        </div>
      ) : (
        <div className="table-wrapper">
          <table className="findings-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Run ID</th>
                <th>Status</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Confirmed</th>
                <th>FP</th>
                <th>Tokens</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sorted.map(r => <RunRow key={r.id} run={r} />)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
