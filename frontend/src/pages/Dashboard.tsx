/**
 * Dashboard — Executive overview with KPIs, trend charts, recent findings.
 */

import React, { useMemo } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts';
import {
  ShieldAlert, CheckCircle, Clock, TrendingDown,
  Activity, Database, GitBranch, AlertTriangle,
  ArrowUpRight, Zap, Target, FlaskConical,
} from 'lucide-react';
import type { Finding, ScanRun, Repository } from '../types';

// ── Palette ───────────────────────────────────────────────────────────────────

const SEV: Record<string, string> = {
  CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#fbbf24', LOW: '#a3e635', INFO: '#94a3b8',
};

// ── Sub-components ─────────────────────────────────────────────────────────────

interface KpiCardProps {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sub?: string;
  accent: string;
  trend?: { direction: 'up' | 'down'; label: string };
}

function KpiCard({ icon, label, value, sub, accent, trend }: KpiCardProps) {
  return (
    <div className="kpi-card" style={{ '--accent': accent } as React.CSSProperties}>
      <div className="kpi-icon" style={{ background: `${accent}18`, color: accent }}>{icon}</div>
      <div className="kpi-body">
        <span className="kpi-label">{label}</span>
        <span className="kpi-value" style={{ color: accent }}>{value}</span>
        {sub && <span className="kpi-sub">{sub}</span>}
        {trend && (
          <span className={`kpi-trend kpi-trend--${trend.direction}`}>
            <ArrowUpRight size={11} style={{ transform: trend.direction === 'down' ? 'rotate(90deg)' : 'none' }} />
            {trend.label}
          </span>
        )}
      </div>
    </div>
  );
}

interface DashboardProps {
  findings: Finding[];
  scanRuns: ScanRun[];
  repositories: Repository[];
  onNavigate: (page: string) => void;
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function Dashboard({ findings, scanRuns, repositories, onNavigate }: DashboardProps) {
  // KPI derivations
  const open = findings.filter(f => f.status === 'new' || f.status === 'confirmed');
  const critical = open.filter(f => f.severity === 'CRITICAL');
  const high = open.filter(f => f.severity === 'HIGH');
  const now = Date.now();
  const oneWeek = 7 * 24 * 60 * 60 * 1000;
  const fixedThisWeek = findings.filter(f => f.status === 'fixed' && f.fixedAt && (now - f.fixedAt < oneWeek));
  const fpCount = findings.filter(f => f.aiVerdict === 'FP').length;
  const fpRate = findings.length > 0 ? ((fpCount / findings.length) * 100).toFixed(1) : '0.0';

  // Recent critical findings (top 5)
  const recentCritical = useMemo(() =>
    [...findings]
      .filter(f => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && f.status !== 'false_positive')
      .sort((a, b) => b.firstDetected - a.firstDetected)
      .slice(0, 5),
    [findings]
  );

  // Severity breakdown for pie chart
  const sevBreakdown = useMemo(() => {
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const f of open) counts[f.severity] = (counts[f.severity] || 0) + 1;
    return Object.entries(counts).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }));
  }, [open]);

  // Recent scan runs for activity feed
  const recentRuns = useMemo(() => [...scanRuns].sort((a, b) => b.startedAt - a.startedAt).slice(0, 6), [scanRuns]);

  // Synthetic trend data (7 days rolling from findings timestamps)
  const trendData = useMemo(() => {
    const days: { day: string; new: number; fixed: number; fp: number }[] = [];
    for (let i = 6; i >= 0; i--) {
      const start = now - (i + 1) * oneWeek / 7;
      const end = now - i * oneWeek / 7;
      days.push({
        day: new Date(start).toLocaleDateString('en', { weekday: 'short' }),
        new: findings.filter(f => f.firstDetected >= start && f.firstDetected < end).length,
        fixed: findings.filter(f => f.status === 'fixed' && f.fixedAt && f.fixedAt >= start && f.fixedAt < end).length,
        fp: findings.filter(f => f.aiVerdict === 'FP' && f.firstDetected >= start && f.firstDetected < end).length,
      });
    }
    return days;
  }, [findings, now, oneWeek]);

  // Status breakdown for bar chart
  const statusData = useMemo(() => [
    { label: 'New', value: findings.filter(f => f.status === 'new').length, color: '#f87171' },
    { label: 'Confirmed', value: findings.filter(f => f.status === 'confirmed').length, color: '#fb923c' },
    { label: 'Fixed', value: findings.filter(f => f.status === 'fixed').length, color: '#34d399' },
    { label: 'Accepted', value: findings.filter(f => f.status === 'accepted_risk').length, color: '#fbbf24' },
    { label: 'FP', value: findings.filter(f => f.status === 'false_positive').length, color: 'var(--color-text-muted)' },
  ], [findings]);

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-subtitle">Real-time overview of your security posture across all repositories</p>
        </div>
        <button className="btn-primary" onClick={() => onNavigate('scan')}>
          <Zap size={15} /> New Scan
        </button>
      </div>

      {/* KPI row */}
      <div className="kpi-grid">
        <KpiCard
          icon={<ShieldAlert size={20} />}
          label="Critical Open" value={critical.length}
          accent="#f87171"
          sub={`+${high.length} HIGH`}
          trend={critical.length > 0 ? { direction: 'up', label: 'Needs attention' } : undefined}
        />
        <KpiCard
          icon={<CheckCircle size={20} />}
          label="Recently Fixed" value={fixedThisWeek.length}
          accent="#34d399"
          sub="Resolved findings"
          trend={fixedThisWeek.length > 0 ? { direction: 'down', label: 'Improving' } : undefined}
        />
        <KpiCard
          icon={<TrendingDown size={20} />}
          label="False Positive Rate" value={`${fpRate}%`}
          accent="#a78bfa"
          sub="AI-identified noise"
        />
        <KpiCard
          icon={<Activity size={20} />}
          label="Total Scans" value={scanRuns.length}
          accent="#38bdf8"
          sub={`${repositories.length} repos monitored`}
        />
        <KpiCard
          icon={<Database size={20} />}
          label="All Findings" value={findings.length}
          accent="#fbbf24"
          sub={`${open.length} open`}
        />
        <KpiCard
          icon={<Clock size={20} />}
          label="Avg Scan Time"
          value={
            scanRuns.filter(r => r.metrics).length > 0
              ? `${Math.round(scanRuns.filter(r => r.metrics).reduce((a, r) => a + (r.metrics!.durationSeconds || 0), 0) / scanRuns.filter(r => r.metrics).length)}s`
              : '—'
          }
          accent="#64748b"
          sub="Per repository"
        />
      </div>

      {/* Charts row */}
      <div className="charts-grid">
        {/* Trend Area Chart */}
        <div className="chart-card chart-card--wide">
          <div className="chart-header">
            <span className="chart-title">Finding Activity — Last 7 Days</span>
          </div>
          {findings.length === 0 ? (
            <EmptyChart label="Run a scan to populate trend data" />
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={trendData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradNew" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f87171" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradFixed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#34d399" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#34d399" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#0d1726', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="new" name="New" stroke="#f87171" fill="url(#gradNew)" strokeWidth={2} />
                <Area type="monotone" dataKey="fixed" name="Fixed" stroke="#34d399" fill="url(#gradFixed)" strokeWidth={2} />
                <Area type="monotone" dataKey="fp" name="FP Eliminated" stroke="#a78bfa" fill="none" strokeWidth={1.5} strokeDasharray="4 2" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Severity Pie */}
        <div className="chart-card">
          <div className="chart-header">
            <span className="chart-title">Open by Severity</span>
          </div>
          {sevBreakdown.length === 0 ? (
            <EmptyChart label="No open findings" />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
              <ResponsiveContainer width="100%" height={150}>
                <PieChart>
                  <Pie data={sevBreakdown} cx="50%" cy="50%" innerRadius={42} outerRadius={68} paddingAngle={3} dataKey="value">
                    {sevBreakdown.map((entry) => (
                      <Cell key={entry.name} fill={SEV[entry.name] || '#64748b'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#0d1726', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center' }}>
                {sevBreakdown.map(s => (
                  <span key={s.name} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: SEV[s.name] }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: SEV[s.name], display: 'inline-block' }} />
                    {s.name} ({s.value})
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Status Bar Chart */}
        <div className="chart-card">
          <div className="chart-header">
            <span className="chart-title">Finding Status</span>
          </div>
          {findings.length === 0 ? (
            <EmptyChart label="No findings yet" />
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={statusData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#0d1726', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="value" name="Count" radius={[4, 4, 0, 0]}>
                  {statusData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Bottom row: recent findings + activity */}
      <div className="bottom-grid">
        {/* Recent Critical Findings */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title"><AlertTriangle size={14} style={{ color: '#f87171', display: 'inline', marginRight: 6 }} />Recent Critical & High Findings</span>
            <button className="link-btn" onClick={() => onNavigate('findings')}>View all →</button>
          </div>
          {recentCritical.length === 0 ? (
            <div className="empty-state">No critical or high findings. Great job! 🛡️</div>
          ) : (
            <div className="finding-list">
              {recentCritical.map(f => (
                <div key={f.id} className="finding-row" onClick={() => onNavigate('findings')}>
                  <div className="finding-row__sev" style={{ background: `${SEV[f.severity]}18`, color: SEV[f.severity] }}>
                    {f.severity}
                  </div>
                  <div className="finding-row__body">
                    <span className="finding-row__title">{f.title || f.description.slice(0, 60)}</span>
                    <span className="finding-row__meta">{f.file}:{f.line} · {f.repository}</span>
                  </div>
                  <div className={`finding-row__status finding-row__status--${f.status}`}>{f.status.replace('_', ' ')}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Scan Activity Feed */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title"><Activity size={14} style={{ color: '#38bdf8', display: 'inline', marginRight: 6 }} />Recent Scans</span>
            <button className="link-btn" onClick={() => onNavigate('scans')}>View history →</button>
          </div>
          {recentRuns.length === 0 ? (
            <div className="empty-state">
              No scans yet. <button className="link-btn" onClick={() => onNavigate('scan')}>Start one →</button>
            </div>
          ) : (
            <div className="activity-list">
              {recentRuns.map(r => (
                <div key={r.id} className="activity-row">
                  <div className={`activity-row__dot activity-row__dot--${r.status}`} />
                  <div className="activity-row__body">
                    <span className="activity-row__name">
                      {r.type === 'repo' ? <><GitBranch size={11} style={{ display: 'inline', marginRight: 3 }} />{r.repository?.split('/').pop() || 'Repository'}</> : <><FlaskConical size={11} style={{ display: 'inline', marginRight: 3 }} />Sandbox Cycle {(r as any).cycle || ''}</>}
                    </span>
                    <span className="activity-row__meta">
                      {new Date(r.startedAt).toLocaleString()} · {r.confirmedCount} confirmed · {r.fpCount} FP
                    </span>
                  </div>
                  <span className={`activity-row__badge activity-row__badge--${r.status}`}>{r.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Repositories */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title"><Database size={14} style={{ color: '#a78bfa', display: 'inline', marginRight: 6 }} />Monitored Repositories</span>
            <button className="link-btn" onClick={() => onNavigate('repositories')}>Manage →</button>
          </div>
          {repositories.length === 0 ? (
            <div className="empty-state">
              No repositories. <button className="link-btn" onClick={() => onNavigate('repositories')}>Add one →</button>
            </div>
          ) : (
            <div className="repo-list">
              {repositories.slice(0, 5).map(r => (
                <div key={r.id} className="repo-row">
                  <Target size={14} style={{ color: '#a78bfa', flexShrink: 0 }} />
                  <div className="repo-row__body">
                    <span className="repo-row__name">{r.name}</span>
                    <span className="repo-row__meta">{r.url}</span>
                  </div>
                  <div className="repo-row__counts">
                    {r.criticalCount > 0 && <span style={{ color: '#f87171', fontSize: 11 }}>{r.criticalCount} C</span>}
                    {r.highCount > 0 && <span style={{ color: '#fb923c', fontSize: 11 }}>{r.highCount} H</span>}
                    <span style={{ color: '#64748b', fontSize: 11 }}>{r.openFindings} open</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function EmptyChart({ label }: { label: string }) {
  return (
    <div style={{ height: 150, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-text-muted)', fontSize: 13, fontStyle: 'italic' }}>
      {label}
    </div>
  );
}
