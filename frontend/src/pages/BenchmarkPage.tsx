/**
 * BenchmarkPage — Phase 1 CVE Recall Dashboard
 * Real-time benchmark metrics: Recall, FP Rate, F1, Severity Accuracy, per-CVE evidence.
 */

import React, { useState, useEffect, useMemo } from 'react';
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  BarChart, Bar, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer,
  Legend,
} from 'recharts';
import {
  Target, ShieldCheck, Zap, TrendingUp, AlertTriangle,
  CheckCircle2, XCircle, Clock, RefreshCw, ExternalLink,
  ChevronDown, ChevronRight, FlaskConical, BarChart2,
  Terminal, BookOpen, Award,
} from 'lucide-react';
import { useStore } from '../useStore';

// ── Palette ─────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#fbbf24', LOW: '#a3e635', INFO: '#94a3b8',
};
const ACCENT = '#0ea5e9';
const ACCENT2 = '#8b5cf6';
const GREEN = '#34d399';
const RED = '#f87171';

// ── Types ────────────────────────────────────────────────────────────────────

interface BenchmarkSummary {
  cases: number;
  complete_vulnerable_swarm_scans: number;
  complete_patched_swarm_scans: number;
  incomplete_or_failed_swarm_scans: number;
  swarm: {
    true_positives: number;
    false_positives: number;
    false_negatives: number;
    true_negatives: number;
    precision: number | null;
    recall: number | null;
    f1: number | null;
    false_positive_rate: number | null;
    severity_accuracy: number | null;
    severity_cases: number;
  };
  sast_baseline: {
    vulnerable_snapshots_detected: number;
    patched_snapshots_still_flagged: number;
    incomplete_snapshots: number;
  };
  per_case: PerCaseScore[];
}

interface PerCaseScore {
  cve_id: string;
  vulnerable_scan_status: string;
  patched_scan_status: string;
  swarm_true_positive: boolean | null;
  swarm_false_positive_after_patch: boolean | null;
  sast_detected_vulnerable: boolean | null;
  sast_still_flags_after_patch: boolean | null;
  severity_correct: boolean | null;
}

interface ManifestCase {
  cve_id: string;
  project: string;
  severity?: string;
  cwe?: string;
  match_keywords?: string[];
  advisory_url?: string;
}

interface BenchmarkData {
  report: {
    schema_version: number;
    started_at: number;
    finished_at?: number;
    manifest: string;
    model: string;
    challenger_model: string;
    cases: any[];
    summary: BenchmarkSummary;
    updated_at: number;
  } | null;
  manifest: { cases: ManifestCase[] } | null;
  report_available: boolean;
  manifest_cases: number;
}

// ── Sub-components ───────────────────────────────────────────────────────────

function MetricCard({
  label, value, sub, accent, icon, target,
}: {
  label: string; value: string | number; sub?: string; accent: string; icon: React.ReactNode; target?: string;
}) {
  return (
    <div style={{
      background: 'rgba(13,23,38,0.6)', border: `1px solid ${accent}22`, borderRadius: 12,
      padding: '18px 22px', display: 'flex', flexDirection: 'column', gap: 6,
      position: 'relative', overflow: 'hidden',
    }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${accent}, ${accent}44)` }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: accent, fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        {icon}{label}
      </div>
      <div style={{ fontSize: 32, fontWeight: 800, color: accent, letterSpacing: '-0.03em', lineHeight: 1.1, fontFamily: "'JetBrains Mono', monospace" }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: 11, color: '#64748b' }}>{sub}</div>}
      {target && <div style={{ fontSize: 11, color: '#475569' }}>Target: <span style={{ color: accent }}>{target}</span></div>}
    </div>
  );
}

function StatusDot({ ok, partial }: { ok: boolean | null; partial?: boolean }) {
  if (ok === null) return <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#334155', display: 'inline-block' }} />;
  if (partial) return <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#fbbf24', display: 'inline-block' }} />;
  return <span style={{ width: 10, height: 10, borderRadius: '50%', background: ok ? GREEN : RED, display: 'inline-block', boxShadow: `0 0 6px ${ok ? GREEN : RED}66` }} />;
}

function CVERow({ score, meta, defaultExpanded }: { score: PerCaseScore; meta?: ManifestCase; defaultExpanded?: boolean }) {
  const [open, setOpen] = useState(defaultExpanded ?? false);
  const severity = meta?.severity || 'UNKNOWN';
  const sevColor = SEV_COLOR[severity] || '#94a3b8';

  const swarmDetected = score.swarm_true_positive === true;
  const swarmFP = score.swarm_false_positive_after_patch === true;
  const sastDetected = score.sast_detected_vulnerable === true;
  const incomplete = score.vulnerable_scan_status !== 'complete' && score.vulnerable_scan_status !== 'partial';

  return (
    <div style={{ border: '1px solid rgba(255,255,255,0.05)', borderRadius: 8, overflow: 'hidden', transition: 'border-color 0.2s' }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          width: '100%', background: 'rgba(13,23,38,0.5)', border: 'none', cursor: 'pointer',
          padding: '10px 16px', display: 'grid', alignItems: 'center',
          gridTemplateColumns: '1fr auto auto auto auto auto auto',
          gap: 12, color: 'var(--color-text)', textAlign: 'left',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {open ? <ChevronDown size={13} style={{ color: '#64748b', flexShrink: 0 }} /> : <ChevronRight size={13} style={{ color: '#64748b', flexShrink: 0 }} />}
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700, color: '#0ea5e9' }}>{score.cve_id}</span>
          {meta?.project && <span style={{ fontSize: 11, color: '#64748b' }}>{meta.project}</span>}
        </div>
        <span style={{ fontSize: 11, fontWeight: 700, color: sevColor, background: `${sevColor}18`, padding: '2px 8px', borderRadius: 4, letterSpacing: '0.04em' }}>{severity}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#94a3b8' }}>
          <StatusDot ok={score.swarm_true_positive} />
          <span style={{ display: window.innerWidth > 900 ? 'inline' : 'none' }}>Swarm TP</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#94a3b8' }}>
          <StatusDot ok={score.swarm_false_positive_after_patch === false} />
          <span style={{ display: window.innerWidth > 900 ? 'inline' : 'none' }}>No Post-Patch FP</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#94a3b8' }}>
          <StatusDot ok={score.sast_detected_vulnerable} />
          <span style={{ display: window.innerWidth > 900 ? 'inline' : 'none' }}>SAST Baseline</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#94a3b8' }}>
          <StatusDot ok={score.severity_correct} />
          <span style={{ display: window.innerWidth > 900 ? 'inline' : 'none' }}>Sev. Accuracy</span>
        </div>
        <span style={{
          fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 20,
          background: incomplete ? 'rgba(51,65,85,0.5)' : swarmDetected ? `${GREEN}22` : `${RED}22`,
          color: incomplete ? '#64748b' : swarmDetected ? GREEN : RED,
          letterSpacing: '0.06em', textTransform: 'uppercase',
        }}>
          {incomplete ? 'PENDING' : swarmDetected ? 'DETECTED' : 'MISSED'}
        </span>
      </button>

      {open && (
        <div style={{ padding: '14px 18px 14px 40px', background: 'rgba(2,6,23,0.3)', display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 8 }}>
            {[
              { label: 'Swarm True Positive', val: score.swarm_true_positive, color: swarmDetected ? GREEN : RED },
              { label: 'Post-patch False Positive', val: score.swarm_false_positive_after_patch, color: swarmFP ? RED : GREEN },
              { label: 'SAST Baseline Detected', val: score.sast_detected_vulnerable, color: sastDetected ? GREEN : '#94a3b8' },
              { label: 'SAST Post-patch FP', val: score.sast_still_flags_after_patch, color: score.sast_still_flags_after_patch ? RED : GREEN },
              { label: 'Severity Accuracy', val: score.severity_correct, color: score.severity_correct ? GREEN : '#fbbf24' },
            ].map(({ label, val, color }) => (
              <div key={label} style={{ background: 'rgba(13,23,38,0.5)', borderRadius: 6, padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: '#64748b' }}>{label}</span>
                <span style={{ fontSize: 12, fontWeight: 700, color }}>
                  {val === null ? '—' : val === true ? '✓ YES' : '✗ NO'}
                </span>
              </div>
            ))}
          </div>
          {meta?.cwe && <div style={{ fontSize: 11, color: '#64748b' }}>CWE: <span style={{ color: '#fbbf24' }}>{meta.cwe}</span></div>}
          {meta?.match_keywords && meta.match_keywords.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {meta.match_keywords.map(kw => (
                <span key={kw} style={{ fontSize: 10, padding: '2px 6px', background: 'rgba(14,165,233,0.1)', borderRadius: 4, color: '#38bdf8', fontFamily: "'JetBrains Mono', monospace" }}>
                  {kw}
                </span>
              ))}
            </div>
          )}
          {meta?.advisory_url && (
            <a href={meta.advisory_url} target="_blank" rel="noopener noreferrer"
              style={{ fontSize: 11, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 4, textDecoration: 'none' }}>
              <ExternalLink size={10} /> Advisory →
            </a>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function BenchmarkPage() {
  const store = useStore();
  const [data, setData] = useState<BenchmarkData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCmd, setShowCmd] = useState(false);

  const API = window.location.origin.includes('5173') ? 'http://127.0.0.1:8001' : '';

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const headers = { Authorization: `Bearer ${store.apiKey}` };
      const res = await fetch(`${API}/api/benchmark`, { headers });
      if (!res.ok) throw new Error(`API returned ${res.status}`);
      setData(await res.json());
    } catch (e: any) {
      setError(e.message || 'Failed to load benchmark data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, [store.apiKey]);

  const summary = data?.report?.summary;
  const swarm = summary?.swarm;
  const manifest = data?.manifest;

  // Build per-case lookup map by CVE ID
  const metaByID = useMemo(() => {
    const m: Record<string, ManifestCase> = {};
    for (const c of manifest?.cases ?? []) m[c.cve_id] = c;
    return m;
  }, [manifest]);

  // Radar data for capability overview
  const radarData = useMemo(() => [
    { metric: 'Recall', swarm: swarm?.recall != null ? Math.round(swarm.recall * 100) : 0, target: 90 },
    { metric: 'Precision', swarm: swarm?.precision != null ? Math.round(swarm.precision * 100) : 0, target: 88 },
    { metric: 'F1', swarm: swarm?.f1 != null ? Math.round(swarm.f1 * 100) : 0, target: 89 },
    { metric: 'Sev. Accuracy', swarm: swarm?.severity_accuracy != null ? Math.round(swarm.severity_accuracy * 100) : 0, target: 80 },
    { metric: 'FP Rejection', swarm: swarm?.false_positive_rate != null ? Math.round((1 - swarm.false_positive_rate) * 100) : 0, target: 88 },
  ], [swarm]);

  // Per-severity breakdown
  const sevBreakdown = useMemo(() => {
    if (!summary?.per_case) return [];
    const counts: Record<string, { total: number; detected: number }> = {};
    for (const pc of summary.per_case) {
      const meta = metaByID[pc.cve_id];
      const sev = meta?.severity || 'UNKNOWN';
      if (!counts[sev]) counts[sev] = { total: 0, detected: 0 };
      counts[sev].total++;
      if (pc.swarm_true_positive === true) counts[sev].detected++;
    }
    return Object.entries(counts).map(([name, { total, detected }]) => ({
      name,
      recall: total > 0 ? Math.round((detected / total) * 100) : 0,
      color: SEV_COLOR[name] || '#94a3b8',
    }));
  }, [summary, metaByID]);

  // ── Empty state ──────────────────────────────────────────────────────────────

  if (loading) return (
    <div className="page-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#64748b', gap: 12, height: 300 }}>
      <RefreshCw size={20} style={{ animation: 'spin 1.2s linear infinite' }} /> Loading benchmark data…
    </div>
  );

  if (!store.apiKey) return (
    <div className="page-container">
      <div style={{ background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 10, padding: 24, textAlign: 'center', color: '#f87171' }}>
        <AlertTriangle size={28} style={{ marginBottom: 12 }} />
        <p style={{ margin: 0, fontWeight: 600 }}>API key required.</p>
        <p style={{ margin: '8px 0 0', fontSize: 12, color: '#94a3b8' }}>Open Settings (top-right ⚙) to enter your Swarm API key.</p>
      </div>
    </div>
  );

  if (error) return (
    <div className="page-container">
      <div style={{ background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 10, padding: 24, color: '#f87171', display: 'flex', gap: 12, alignItems: 'flex-start' }}>
        <AlertTriangle size={20} style={{ flexShrink: 0, marginTop: 2 }} />
        <div>
          <p style={{ margin: 0, fontWeight: 600 }}>Benchmark API error: {error}</p>
          <p style={{ margin: '6px 0 0', fontSize: 12, color: '#94a3b8' }}>Ensure the Swarm backend is running.</p>
          <button onClick={fetchData} className="btn-primary" style={{ marginTop: 12, padding: '6px 14px', fontSize: 12 }}>Retry</button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="page-container">
      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Award size={22} style={{ color: '#fbbf24' }} /> CVE Benchmark — Phase 1
          </h1>
          <p className="page-subtitle">
            Real CVE detection metrics vs. patched baselines · {data?.manifest_cases ?? 0} cases in manifest
            {summary && ` · ${summary.complete_vulnerable_swarm_scans} scans completed`}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={() => setShowCmd(v => !v)} style={{ background: 'rgba(14,165,233,0.1)', border: '1px solid rgba(14,165,233,0.2)', color: '#38bdf8', borderRadius: 8, padding: '6px 14px', fontSize: 12, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Terminal size={13} /> Run Command
          </button>
          <button onClick={fetchData} className="btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      {/* Run command box */}
      {showCmd && (
        <div style={{ background: 'rgba(2,6,23,0.9)', border: '1px solid rgba(14,165,233,0.2)', borderRadius: 8, padding: '14px 18px', marginBottom: 20, fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <Terminal size={14} style={{ color: '#64748b', flexShrink: 0 }} />
          <span style={{ color: '#94a3b8' }}>python</span> cycle11_ollama_swarm/benchmark_cves.py --manifest benchmarks/cve_manifest.json --output-dir results/cve_benchmark
          <span style={{ marginLeft: 'auto', fontSize: 11, color: '#475569' }}>Add --max-chunks 3 for a quick smoke test</span>
        </div>
      )}

      {/* ── No report yet ── */}
      {!data?.report_available && (
        <div style={{ background: 'rgba(251,191,36,0.06)', border: '1px solid rgba(251,191,36,0.15)', borderRadius: 10, padding: 24, marginBottom: 24, display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          <FlaskConical size={24} style={{ color: '#fbbf24', flexShrink: 0, marginTop: 2 }} />
          <div>
            <p style={{ margin: 0, fontWeight: 600, color: '#fbbf24', fontSize: 15 }}>No benchmark results yet</p>
            <p style={{ margin: '6px 0 0', fontSize: 12, color: '#94a3b8' }}>
              The benchmark harness is configured with <strong style={{ color: '#f8fafc' }}>{data?.manifest_cases ?? 20} real CVE cases</strong>.
              Run the command above to start the paired vulnerable/patched evaluation.
              Results write incrementally so you can check progress live.
            </p>
            <div style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {['Django (Python)', 'Flask (Python)', 'PyJWT (Python)', 'Requests (Python)', 'Starlette (Python)', 'webpack (JS)', 'vm2 (JS)', 'xmldom (JS)', 'golang/net (Go)', 'golang/go (Go)'].map(p => (
                <span key={p} style={{ fontSize: 10, padding: '2px 8px', background: 'rgba(14,165,233,0.08)', borderRadius: 4, color: '#38bdf8' }}>{p}</span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── KPI Metrics Row ── */}
      {summary && swarm && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(155px, 1fr))', gap: 14, marginBottom: 24 }}>
            <MetricCard
              label="Recall" icon={<Target size={12} />}
              value={swarm.recall != null ? `${Math.round(swarm.recall * 100)}%` : '—'}
              sub={`${swarm.true_positives} of ${swarm.true_positives + swarm.false_negatives} CVEs detected`}
              accent={ACCENT} target=">90%"
            />
            <MetricCard
              label="Precision" icon={<ShieldCheck size={12} />}
              value={swarm.precision != null ? `${Math.round(swarm.precision * 100)}%` : '—'}
              sub={`${swarm.false_positives} post-patch FPs`}
              accent={GREEN} target=">85%"
            />
            <MetricCard
              label="F1 Score" icon={<BarChart2 size={12} />}
              value={swarm.f1 != null ? `${Math.round(swarm.f1 * 100)}%` : '—'}
              sub="Harmonic mean of Recall + Precision"
              accent={ACCENT2} target=">87%"
            />
            <MetricCard
              label="FP Rate" icon={<TrendingUp size={12} />}
              value={swarm.false_positive_rate != null ? `${Math.round(swarm.false_positive_rate * 100)}%` : '—'}
              sub="Post-patch false alarms"
              accent="#fb923c" target="<12%"
            />
            <MetricCard
              label="Sev. Accuracy" icon={<Award size={12} />}
              value={swarm.severity_accuracy != null ? `${Math.round(swarm.severity_accuracy * 100)}%` : '—'}
              sub={`${swarm.severity_cases} severity comparisons`}
              accent="#fbbf24" target=">80%"
            />
            <MetricCard
              label="Cases Run" icon={<FlaskConical size={12} />}
              value={`${summary.complete_vulnerable_swarm_scans}/${summary.cases}`}
              sub={`${summary.incomplete_or_failed_swarm_scans} pending/failed`}
              accent="#64748b" target={`${summary.cases} total`}
            />
          </div>

          {/* ── Charts Row ── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
            {/* Radar Chart */}
            <div style={{ background: 'rgba(13,23,38,0.5)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Target size={14} style={{ color: ACCENT }} /> Capability Radar
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <RadarChart data={radarData}>
                  <PolarGrid stroke="rgba(255,255,255,0.08)" />
                  <PolarAngleAxis dataKey="metric" tick={{ fill: '#64748b', fontSize: 10 }} />
                  <Radar name="Swarm" dataKey="swarm" stroke={ACCENT} fill={ACCENT} fillOpacity={0.15} strokeWidth={2} />
                  <Radar name="Target" dataKey="target" stroke="#fbbf24" fill="none" strokeDasharray="4 2" strokeWidth={1.5} />
                  <Legend iconType="line" wrapperStyle={{ fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: '#0d1726', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 11 }}
                    formatter={(v: number) => `${v}%`} />
                </RadarChart>
              </ResponsiveContainer>
            </div>

            {/* Per-severity bar */}
            <div style={{ background: 'rgba(13,23,38,0.5)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 8 }}>
                <BarChart2 size={14} style={{ color: ACCENT2 }} /> Recall by Severity
              </div>
              {sevBreakdown.length === 0 ? (
                <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#475569', fontSize: 12, fontStyle: 'italic' }}>
                  Run benchmark to populate
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={sevBreakdown} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                    <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} tickFormatter={(v: number) => `${v}%`} />
                    <Tooltip contentStyle={{ background: '#0d1726', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 11 }}
                      formatter={(v: number) => `${v}%`} />
                    <Bar dataKey="recall" name="Recall %" radius={[4, 4, 0, 0]}>
                      {sevBreakdown.map((entry) => (
                        <Cell key={entry.name} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* ── SAST Baseline Comparison ── */}
          <div style={{ background: 'rgba(13,23,38,0.5)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 20, marginBottom: 24 }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 14, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Zap size={14} style={{ color: '#fbbf24' }} /> Swarm vs. SAST Baseline
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
              {[
                {
                  label: 'Swarm CVE Detection',
                  val: swarm.true_positives,
                  total: swarm.true_positives + swarm.false_negatives,
                  color: ACCENT,
                },
                {
                  label: 'SAST Baseline Detection',
                  val: summary.sast_baseline.vulnerable_snapshots_detected,
                  total: summary.complete_vulnerable_swarm_scans,
                  color: '#a78bfa',
                },
                {
                  label: 'Swarm Post-Patch FP',
                  val: swarm.false_positives,
                  total: swarm.true_negatives + swarm.false_positives,
                  color: '#fb923c',
                  inverse: true,
                },
                {
                  label: 'SAST Post-Patch FP',
                  val: summary.sast_baseline.patched_snapshots_still_flagged,
                  total: summary.complete_patched_swarm_scans,
                  color: '#f87171',
                  inverse: true,
                },
              ].map(({ label, val, total, color, inverse }) => {
                const pct = total > 0 ? Math.round((val / total) * 100) : 0;
                const good = inverse ? pct < 20 : pct > 80;
                return (
                  <div key={label} style={{ background: 'rgba(2,6,23,0.4)', borderRadius: 8, padding: '12px 14px' }}>
                    <div style={{ fontSize: 11, color: '#64748b', marginBottom: 8 }}>{label}</div>
                    <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: "'JetBrains Mono', monospace" }}>
                      {val}/{total}
                      <span style={{ fontSize: 13, marginLeft: 6, color: good ? GREEN : '#fb923c' }}>({pct}%)</span>
                    </div>
                    <div style={{ marginTop: 8, height: 4, background: 'rgba(255,255,255,0.05)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2, transition: 'width 0.8s ease' }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}

      {/* ── Per-CVE Results Table ── */}
      <div style={{ background: 'rgba(13,23,38,0.5)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 20 }}>
        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 14, color: '#f8fafc', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <BookOpen size={14} style={{ color: '#38bdf8' }} /> Per-CVE Results ({data?.manifest_cases ?? 0} in manifest)
          </span>
          {summary && (
            <div style={{ display: 'flex', gap: 12, fontSize: 11, color: '#64748b' }}>
              <span style={{ color: GREEN }}>✓ {summary.swarm?.true_positives ?? 0} Detected</span>
              <span style={{ color: RED }}>✗ {summary.swarm?.false_negatives ?? 0} Missed</span>
              <span style={{ color: '#64748b' }}>⏳ {(data?.manifest_cases ?? 0) - (summary.complete_vulnerable_swarm_scans ?? 0)} Pending</span>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {/* Cases with results */}
          {summary?.per_case?.map((score, i) => (
            <CVERow key={score.cve_id} score={score} meta={metaByID[score.cve_id]} defaultExpanded={i === 0} />
          ))}

          {/* Pending cases (in manifest but not yet run) */}
          {manifest?.cases
            .filter(c => !summary?.per_case?.find(p => p.cve_id === c.cve_id))
            .map(c => {
              const sevColor = SEV_COLOR[c.severity || 'UNKNOWN'] || '#94a3b8';
              return (
                <div key={c.cve_id} style={{ background: 'rgba(13,23,38,0.3)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: 8, padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 12, opacity: 0.6 }}>
                  <Clock size={13} style={{ color: '#475569', flexShrink: 0 }} />
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700, color: '#475569' }}>{c.cve_id}</span>
                  {c.project && <span style={{ fontSize: 11, color: '#334155' }}>{c.project}</span>}
                  {c.severity && <span style={{ fontSize: 10, fontWeight: 700, color: sevColor, background: `${sevColor}11`, padding: '2px 7px', borderRadius: 4, letterSpacing: '0.04em', marginLeft: 'auto' }}>{c.severity}</span>}
                  <span style={{ fontSize: 10, color: '#334155', fontStyle: 'italic' }}>PENDING</span>
                </div>
              );
            })
          }

          {!manifest?.cases?.length && !summary?.per_case?.length && (
            <div style={{ textAlign: 'center', padding: '32px 0', color: '#475569', fontSize: 13, fontStyle: 'italic' }}>
              No CVE cases available. Ensure the benchmark manifest is deployed.
            </div>
          )}
        </div>
      </div>

      {/* ── Report metadata footer ── */}
      {data?.report && (
        <div style={{ marginTop: 16, display: 'flex', gap: 16, fontSize: 11, color: '#334155', flexWrap: 'wrap' }}>
          <span>Model: <span style={{ color: '#475569' }}>{data.report.model}</span></span>
          <span>Challenger: <span style={{ color: '#475569' }}>{data.report.challenger_model}</span></span>
          {data.report.finished_at && <span>Completed: <span style={{ color: '#475569' }}>{new Date(data.report.finished_at * 1000).toLocaleString()}</span></span>}
          {data.report.updated_at && <span>Last updated: <span style={{ color: '#475569' }}>{new Date(data.report.updated_at * 1000).toLocaleString()}</span></span>}
        </div>
      )}
    </div>
  );
}
