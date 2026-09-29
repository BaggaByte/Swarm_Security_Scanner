/**
 * Findings Database — searchable, filterable finding lifecycle management.
 */

import React, { useState, useMemo, useCallback } from 'react';
import {
  Search, Filter, ChevronDown, ChevronUp, CheckCircle,
  XCircle, AlertOctagon, ShieldOff, Clock, FileCode,
  GitCommit, User, RotateCcw, ExternalLink,
} from 'lucide-react';
import type { Finding, FindingStatus, Severity } from '../types';
import { useStore } from '../useStore';

// ── Severity palette ──────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#fbbf24', LOW: '#a3e635', INFO: '#94a3b8',
};

const STATUS_CONFIG: Record<FindingStatus, { label: string; color: string; icon: React.ReactNode }> = {
  new:           { label: 'New',           color: '#f87171', icon: <AlertOctagon size={13} /> },
  confirmed:     { label: 'Confirmed',     color: '#fb923c', icon: <ShieldOff size={13} /> },
  fixed:         { label: 'Fixed',         color: '#34d399', icon: <CheckCircle size={13} /> },
  accepted_risk: { label: 'Accepted Risk', color: '#fbbf24', icon: <ShieldOff size={13} /> },
  false_positive:{ label: 'False Positive',color: 'var(--color-text-muted)', icon: <XCircle size={13} /> },
};

const VERDICT_CONFIG = {
  TP:           { label: 'True Positive',  color: '#f87171' },
  FP:           { label: 'False Positive', color: 'var(--color-text-muted)' },
  INCONCLUSIVE: { label: 'Inconclusive',   color: '#fbbf24' },
  PENDING:      { label: 'Pending',        color: '#94a3b8' },
};

// ── Components ─────────────────────────────────────────────────────────────────

function SevBadge({ severity }: { severity: string }) {
  const c = SEV_COLOR[severity] || '#94a3b8';
  return (
    <span style={{ color: c, background: `${c}18`, border: `1px solid ${c}44`, borderRadius: 4, padding: '1px 7px', fontSize: 11, fontWeight: 700, letterSpacing: '0.04em', fontFamily: 'JetBrains Mono, monospace' }}>
      {severity}
    </span>
  );
}

function StatusPill({ status, onClick }: { status: FindingStatus; onClick?: () => void }) {
  const { label, color, icon } = STATUS_CONFIG[status];
  return (
    <button
      onClick={onClick}
      title="Click to change status"
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color, background: `${color}18`, border: `1px solid ${color}44`, borderRadius: 20, padding: '2px 10px', fontSize: 11, fontWeight: 600, cursor: onClick ? 'pointer' : 'default', transition: 'all 0.15s' }}
    >
      {icon} {label}
    </button>
  );
}

interface FindingDetailProps {
  finding: Finding;
  onClose: () => void;
  onStatusChange: (id: string, status: FindingStatus) => void;
  onOwnerChange: (id: string, owner: string) => void;
  onRemediationUpdate: (id: string, code: string) => void;
  onExploitUpdate: (id: string, verified: boolean, output: string, exploitPath: string) => void;
}

function FindingDetail({ finding: f, onClose, onStatusChange, onOwnerChange, onRemediationUpdate, onExploitUpdate }: FindingDetailProps) {
  const [editOwner, setEditOwner] = useState(false);
  const [ownerInput, setOwnerInput] = useState(f.owner || '');
  const [isFixing, setIsFixing] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [exploitError, setExploitError] = useState<string | null>(null);
  const [remediationError, setRemediationError] = useState<string | null>(null);

  const { apiKey } = useStore();

  React.useEffect(() => {
    const prevFocus = document.activeElement as HTMLElement;
    const panel = document.getElementById('finding-detail-panel');
    if (panel) panel.focus();
    
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Tab' && panel) {
        const focusable = panel.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
        if (focusable.length) {
          const first = focusable[0] as HTMLElement;
          const last = focusable[focusable.length - 1] as HTMLElement;
          if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };
    
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      if (prevFocus) prevFocus.focus();
    };
  }, []);

  const handleVerifyExploit = async () => {
    setIsVerifying(true);
    setExploitError(null);
    try {
      const API = window.location.origin.includes('5173') ? 'http://127.0.0.1:8001' : '';
      const res = await fetch(`${API}/api/verify`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({
          finding_id: f.id,
          file_path: f.file,
          description: f.description,
          code_snippet: f.codeSnippet || 'Unknown',
          target_url: 'http://sandbox-target:5000'
        })
      });
      if (!res.ok) throw new Error(await res.text() || res.statusText);
      const data = await res.json();
      onExploitUpdate(f.id, data.verified, data.output, data.exploit_code);
    } catch (e: any) {
      setExploitError(e.message || 'Exploit verification failed.');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleAutoFix = async () => {
    setIsFixing(true);
    setRemediationError(null);
    try {
      const API = window.location.origin.includes('5173') ? 'http://127.0.0.1:8001' : '';
      const res = await fetch(`${API}/api/remediate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({
          finding_id: f.id,
          file_path: f.file,
          line_number: f.line,
          severity: f.severity,
          description: f.description,
          code_snippet: f.codeSnippet || 'Unknown',
        })
      });
      if (!res.ok) throw new Error(await res.text() || res.statusText);
      const data = await res.json();
      if (data.suggested_fix) {
        onRemediationUpdate(f.id, data.suggested_fix);
      }
    } catch (e: any) {
      setRemediationError(e.message || 'Remediation generation failed.');
    } finally {
      setIsFixing(false);
    }
  };

  return (
    <div className="detail-overlay" onClick={onClose} onKeyDown={e => e.key === 'Escape' && onClose()}>
      <div id="finding-detail-panel" className="detail-panel" role="dialog" aria-modal="true" aria-labelledby="detail-title" onClick={e => e.stopPropagation()} tabIndex={-1}>
        {/* Header */}
        <div className="detail-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <SevBadge severity={f.severity} />
            <h2 id="detail-title" style={{ margin: 0, color: '#e2e8f0', fontWeight: 600, fontSize: 15 }}>{f.title || 'Security Finding'}</h2>
          </div>
          <button onClick={onClose} aria-label="Close dialog" style={{ color: 'var(--color-text-muted)', background: 'none', border: 'none', cursor: 'pointer', fontSize: 20 }}>×</button>
        </div>

        <div className="detail-body">
          {/* Status row */}
          <div className="detail-section">
            <label className="detail-label">Status</label>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {(Object.keys(STATUS_CONFIG) as FindingStatus[]).map(s => (
                <button
                  key={s}
                  onClick={() => onStatusChange(f.id, s)}
                  style={{
                    padding: '4px 12px', borderRadius: 20, fontSize: 11, fontWeight: 600, cursor: 'pointer',
                    background: f.status === s ? `${STATUS_CONFIG[s].color}30` : 'rgba(255,255,255,0.04)',
                    border: `1px solid ${f.status === s ? STATUS_CONFIG[s].color : 'rgba(255,255,255,0.1)'}`,
                    color: f.status === s ? STATUS_CONFIG[s].color : '#64748b',
                    transition: 'all 0.15s',
                  }}
                >
                  {STATUS_CONFIG[s].label}
                </button>
              ))}
            </div>
          </div>

          {/* Location */}
          <div className="detail-section">
            <label className="detail-label">Location</label>
            <div className="detail-code-block">
              <FileCode size={13} style={{ color: 'var(--color-text-muted)' }} />
              <span>{f.file}:{f.line}</span>
              <span style={{ color: 'var(--color-text-muted)' }}>·</span>
              <span style={{ color: 'var(--color-text-muted)' }}>{f.repository}</span>
            </div>
          </div>

          {/* Description */}
          <div className="detail-section">
            <label className="detail-label">Description</label>
            <p style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.6, margin: 0 }}>{f.description}</p>
          </div>

          {/* AI Verdict */}
          <div className="detail-section">
            <label className="detail-label">AI Swarm Verdict</label>
            <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
              <span style={{
                color: VERDICT_CONFIG[f.aiVerdict]?.color || '#94a3b8',
                background: `${VERDICT_CONFIG[f.aiVerdict]?.color || '#94a3b8'}18`,
                border: `1px solid ${VERDICT_CONFIG[f.aiVerdict]?.color || '#94a3b8'}44`,
                borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 700, flexShrink: 0
              }}>
                {VERDICT_CONFIG[f.aiVerdict]?.label || f.aiVerdict}
              </span>
            </div>
            {f.swarmRationale && (
              <div style={{ marginTop: 8, background: 'rgba(0,0,0,0.3)', borderRadius: 8, padding: '10px 12px', border: '1px solid rgba(255,255,255,0.06)' }}>
                <p style={{ color: '#94a3b8', fontSize: 12, margin: 0, fontStyle: 'italic', lineHeight: 1.6 }}>"{f.swarmRationale}"</p>
              </div>
            )}
          </div>

          {/* Exploit Path */}
          <div className="detail-section">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label className="detail-label">Active Exploit Verification</label>
              <button 
                onClick={handleVerifyExploit}
                disabled={isVerifying}
                style={{ padding: '4px 10px', borderRadius: 6, background: '#f59e0b18', border: '1px solid #f59e0b44', color: '#fbbf24', fontSize: 11, cursor: isVerifying ? 'not-allowed' : 'pointer', fontWeight: 600 }}
              >
                {isVerifying ? 'Executing Exploit Sandbox...' : '🔥 Verify Exploitability'}
              </button>
            </div>
            
            {exploitError && (
              <div style={{ marginTop: 8, color: '#f87171', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(248,113,113,0.1)', padding: '8px 12px', borderRadius: 8 }}>
                <XCircle size={14} /> {exploitError}
              </div>
            )}
            
            {f.exploitVerified !== undefined && !exploitError && (
              <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 6, color: f.exploitVerified ? '#f87171' : '#fbbf24', fontSize: 13, fontWeight: 600 }}>
                {f.exploitVerified ? 'Exploit Successful (Vulnerability Confirmed)' : 'Not verified (Exploit generation/execution failed)'}
              </div>
            )}
            
            {f.exploitPath && !exploitError && (
              <pre style={{ marginTop: 8, background: 'rgba(248,113,113,0.05)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 8, padding: '10px 12px', color: '#fca5a5', fontSize: 12, margin: 0, whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>{f.exploitPath}</pre>
            )}
            
            {f.exploitOutput && !exploitError && (
              <pre style={{ marginTop: 8, background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, padding: '10px 12px', color: '#94a3b8', fontSize: 11, margin: 0, whiteSpace: 'pre-wrap', lineHeight: 1.4 }}>Sandbox Output:\n{f.exploitOutput}</pre>
            )}
          </div>

          {/* Remediation */}
          <div className="detail-section">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label className="detail-label">Remediation Suggestion</label>
              <button 
                onClick={handleAutoFix}
                disabled={isFixing}
                style={{ padding: '4px 10px', borderRadius: 6, background: '#8b5cf618', border: '1px solid #8b5cf644', color: '#a78bfa', fontSize: 11, cursor: isFixing ? 'not-allowed' : 'pointer', fontWeight: 600 }}
              >
                {isFixing ? 'Generating...' : '✨ Generate remediation suggestion'}
              </button>
            </div>
            {remediationError && (
              <div style={{ marginTop: 8, color: '#f87171', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(248,113,113,0.1)', padding: '8px 12px', borderRadius: 8 }}>
                <XCircle size={14} /> {remediationError}
              </div>
            )}
            {f.remediationSuggestion && !remediationError && (
              <pre style={{ background: 'rgba(52,211,153,0.05)', border: '1px solid rgba(52,211,153,0.2)', borderRadius: 8, padding: '10px 12px', color: '#6ee7b7', fontSize: 12, margin: 0, whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>{f.remediationSuggestion}</pre>
            )}
          </div>

          {/* Metadata */}
          <div className="detail-section">
            <label className="detail-label">Metadata</label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {[
                ['CWE', f.cwe || '—'],
                ['OWASP', f.owasp || '—'],
                ['Tool', f.tool],
                ['Rule', f.ruleId || '—'],
                ['First Detected', f.firstDetected ? new Date(f.firstDetected).toLocaleDateString() : '—'],
                ['Last Detected', f.lastDetected ? new Date(f.lastDetected).toLocaleDateString() : '—'],
              ].map(([k, v]) => (
                <div key={k} style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 6, padding: '6px 10px' }}>
                  <div style={{ fontSize: 10, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{k}</div>
                  <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 2 }}>{v}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Owner */}
          <div className="detail-section">
            <label className="detail-label">Owner</label>
            {editOwner ? (
              <div style={{ display: 'flex', gap: 6 }}>
                <input
                  value={ownerInput}
                  onChange={e => setOwnerInput(e.target.value)}
                  placeholder="Assign to team member..."
                  style={{ flex: 1, padding: '6px 10px', borderRadius: 6, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#e2e8f0', fontSize: 13 }}
                />
                <button
                  onClick={() => { onOwnerChange(f.id, ownerInput); setEditOwner(false); }}
                  style={{ padding: '6px 14px', borderRadius: 6, background: '#38bdf818', border: '1px solid #38bdf844', color: '#38bdf8', fontSize: 12, cursor: 'pointer' }}
                >Save</button>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <User size={13} style={{ color: 'var(--color-text-muted)' }} />
                <span style={{ color: f.owner ? '#e2e8f0' : '#475569', fontSize: 13 }}>{f.owner || 'Unassigned'}</span>
                <button onClick={() => setEditOwner(true)} style={{ color: '#38bdf8', background: 'none', border: 'none', fontSize: 12, cursor: 'pointer' }}>Edit</button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main ───────────────────────────────────────────────────────────────────────

interface FindingsPageProps {
  findings: Finding[];
  onStatusChange: (id: string, status: FindingStatus) => void;
  onOwnerChange: (id: string, owner: string) => void;
  onRemediationUpdate: (id: string, code: string) => void;
  onExploitUpdate: (id: string, verified: boolean, output: string, exploitPath: string) => void;
}

export default function FindingsPage({ findings, onStatusChange, onOwnerChange, onRemediationUpdate, onExploitUpdate }: FindingsPageProps) {
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState<string[]>([]);
  const [verdictFilter, setVerdictFilter] = useState<string[]>([]);
  const [repoFilter, setRepoFilter] = useState<string[]>([]);
  const [sortKey, setSortKey] = useState<'firstDetected' | 'severity' | 'status'>('firstDetected');
  const [sortAsc, setSortAsc] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [selected, setSelected] = useState<Finding | null>(null);
  
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;

  const uniqueRepos = useMemo(() => Array.from(new Set(findings.map(f => f.repository))), [findings]);

  const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

  const filtered = useMemo(() => {
    let fs = findings;
    if (search) {
      const q = search.toLowerCase();
      fs = fs.filter(f => f.title?.toLowerCase().includes(q) || f.description.toLowerCase().includes(q) || f.file.toLowerCase().includes(q) || f.repository.toLowerCase().includes(q));
    }
    if (sevFilter.length) fs = fs.filter(f => sevFilter.includes(f.severity));
    if (statusFilter.length) fs = fs.filter(f => statusFilter.includes(f.status));
    if (verdictFilter.length) fs = fs.filter(f => verdictFilter.includes(f.aiVerdict));
    if (repoFilter.length) fs = fs.filter(f => repoFilter.includes(f.repository));

    return [...fs].sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'firstDetected') cmp = a.firstDetected - b.firstDetected;
      if (sortKey === 'severity') cmp = (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5);
      if (sortKey === 'status') cmp = a.status.localeCompare(b.status);
      return sortAsc ? cmp : -cmp;
    });
  }, [findings, search, sevFilter, statusFilter, verdictFilter, repoFilter, sortKey, sortAsc]);

  // Reset to page 1 when filters change
  React.useEffect(() => {
    setPage(1);
  }, [search, sevFilter, statusFilter, verdictFilter, repoFilter]);

  const paginated = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return filtered.slice(start, start + PAGE_SIZE);
  }, [filtered, page]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);

  const isAllFilteredSelected = filtered.length > 0 && filtered.every(f => selectedIds.has(f.id));
  const isSomeFilteredSelected = filtered.length > 0 && filtered.some(f => selectedIds.has(f.id));
  const hiddenSelectedCount = Array.from(selectedIds).filter(id => !filtered.find(f => f.id === id)).length;

  const handleBulkStatus = (status: FindingStatus) => {
    selectedIds.forEach(id => onStatusChange(id, status));
    setSelectedIds(new Set());
  };

  const toggleSort = (key: typeof sortKey) => {
    if (sortKey === key) setSortAsc(v => !v);
    else { setSortKey(key); setSortAsc(false); }
  };

  const toggleFilter = useCallback((arr: string[], setArr: (v: string[]) => void, val: string) => {
    setArr(arr.includes(val) ? arr.filter(x => x !== val) : [...arr, val]);
  }, []);

  const SortIcon = ({ k }: { k: typeof sortKey }) => sortKey === k
    ? (sortAsc ? <ChevronUp size={13} /> : <ChevronDown size={13} />)
    : null;

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Findings Database</h1>
          <p className="page-subtitle">{filtered.length} of {findings.length} findings shown</p>
        </div>
      </div>

      {/* Toolbar */}
      <div className="toolbar">
        <div className="search-box">
          <Search size={15} style={{ color: 'var(--color-text-muted)', flexShrink: 0 }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search findings, files, repositories…"
            className="search-input"
          />
          {search && <button onClick={() => setSearch('')} style={{ color: 'var(--color-text-muted)', background: 'none', border: 'none', cursor: 'pointer', fontSize: 18 }}>×</button>}
        </div>
        <button className={`filter-toggle ${showFilters ? 'filter-toggle--active' : ''}`} onClick={() => setShowFilters(v => !v)}>
          <Filter size={14} /> Filters {(sevFilter.length + statusFilter.length + verdictFilter.length + repoFilter.length) > 0 && <span className="filter-badge">{sevFilter.length + statusFilter.length + verdictFilter.length + repoFilter.length}</span>}
        </button>
        {(sevFilter.length + statusFilter.length + verdictFilter.length + repoFilter.length) > 0 && (
          <button className="link-btn" onClick={() => { setSevFilter([]); setStatusFilter([]); setVerdictFilter([]); setRepoFilter([]); }}>
            <RotateCcw size={12} /> Clear
          </button>
        )}
      </div>

      {/* Bulk actions */}
      {selectedIds.size > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px', background: 'rgba(56,189,248,0.1)', border: '1px solid rgba(56,189,248,0.2)', borderRadius: 8, marginBottom: 16 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: '#38bdf8' }}>
            {selectedIds.size} selected
            {hiddenSelectedCount > 0 && <span style={{ opacity: 0.8, fontWeight: 400 }}> ({hiddenSelectedCount} hidden by filters)</span>}
          </span>
          <div style={{ width: 1, height: 16, background: 'rgba(56,189,248,0.2)' }} />
          <button onClick={() => handleBulkStatus('fixed')} style={{ background: 'none', border: '1px solid #34d39944', color: '#34d399', padding: '4px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer' }}>Mark Fixed</button>
          <button onClick={() => handleBulkStatus('false_positive')} style={{ background: 'none', border: '1px solid #94a3b844', color: '#94a3b8', padding: '4px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer' }}>Mark False Positive</button>
          <button onClick={() => handleBulkStatus('accepted_risk')} style={{ background: 'none', border: '1px solid #fbbf2444', color: '#fbbf24', padding: '4px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer' }}>Accept Risk</button>
        </div>
      )}

      {/* Filter panel */}
      {showFilters && (
        <div className="filter-panel">
          <div className="filter-group">
            <span className="filter-group__label">Severity</span>
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as Severity[]).map(s => (
              <button
                key={s}
                onClick={() => toggleFilter(sevFilter, setSevFilter, s)}
                className={`filter-chip ${sevFilter.includes(s) ? 'filter-chip--active' : ''}`}
                style={{ '--chip-color': SEV_COLOR[s] } as React.CSSProperties}
              >{s}</button>
            ))}
          </div>
          <div className="filter-group">
            <span className="filter-group__label">Status</span>
            {(Object.keys(STATUS_CONFIG) as FindingStatus[]).map(s => (
              <button
                key={s}
                onClick={() => toggleFilter(statusFilter, setStatusFilter, s)}
                className={`filter-chip ${statusFilter.includes(s) ? 'filter-chip--active' : ''}`}
                style={{ '--chip-color': STATUS_CONFIG[s].color } as React.CSSProperties}
              >{STATUS_CONFIG[s].label}</button>
            ))}
          </div>
          <div className="filter-group">
            <span className="filter-group__label">AI Verdict</span>
            {(['TP', 'FP', 'INCONCLUSIVE', 'PENDING']).map(v => (
              <button
                key={v}
                onClick={() => toggleFilter(verdictFilter, setVerdictFilter, v)}
                className={`filter-chip ${verdictFilter.includes(v) ? 'filter-chip--active' : ''}`}
                style={{ '--chip-color': VERDICT_CONFIG[v as keyof typeof VERDICT_CONFIG]?.color } as React.CSSProperties}
              >{v}</button>
            ))}
          </div>
          <div className="filter-group">
            <span className="filter-group__label">Repository</span>
            {uniqueRepos.map(r => (
              <button
                key={r}
                onClick={() => toggleFilter(repoFilter, setRepoFilter, r)}
                className={`filter-chip ${repoFilter.includes(r) ? 'filter-chip--active' : ''}`}
                style={{ '--chip-color': '#38bdf8' } as React.CSSProperties}
              >{r.split('/').pop()}</button>
            ))}
          </div>
        </div>
      )}

      {/* Table */}
      {findings.length === 0 ? (
        <div className="empty-full">
          <ShieldOff size={40} style={{ color: '#1e293b' }} />
          <p style={{ color: 'var(--color-text-muted)', fontSize: 14, marginTop: 12 }}>No findings yet. Run a scan to populate this database.</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="empty-full" style={{ background: 'rgba(255,255,255,0.02)', borderRadius: 12 }}>
          <Filter size={32} style={{ color: 'var(--color-text-muted)' }} />
          <p style={{ color: '#94a3b8', fontSize: 14, marginTop: 12 }}>No findings match your current filters.</p>
          <button onClick={() => { setSearch(''); setSevFilter([]); setStatusFilter([]); setVerdictFilter([]); setRepoFilter([]); }} style={{ marginTop: 12, background: 'none', border: '1px solid #38bdf8', color: '#38bdf8', padding: '6px 12px', borderRadius: 6, fontSize: 12, cursor: 'pointer' }}>Clear Filters</button>
        </div>
      ) : (
        <div className="table-wrapper">
          <table className="findings-table">
            <thead>
              <tr>
                <th style={{ width: 40 }}>
                  <input type="checkbox"
                    aria-label={isAllFilteredSelected ? "Deselect all filtered findings" : "Select all filtered findings"}
                    ref={el => { if (el) el.indeterminate = isSomeFilteredSelected && !isAllFilteredSelected; }}
                    checked={isAllFilteredSelected}
                    onChange={(e) => {
                      if (e.target.checked) setSelectedIds(new Set(filtered.map(f => f.id)));
                      else setSelectedIds(new Set());
                    }}
                    style={{ cursor: 'pointer', accentColor: '#38bdf8' }}
                  />
                </th>
                <th role="button" aria-sort={sortKey === 'severity' ? (sortAsc ? 'ascending' : 'descending') : 'none'} onClick={() => toggleSort('severity')} className="th-sortable" tabIndex={0} onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('severity'))}>Severity <SortIcon k="severity" /></th>
                <th>Finding</th>
                <th>Location</th>
                <th>Repository</th>
                <th>Verdict</th>
                <th role="button" aria-sort={sortKey === 'status' ? (sortAsc ? 'ascending' : 'descending') : 'none'} onClick={() => toggleSort('status')} className="th-sortable" tabIndex={0} onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('status'))}>Status <SortIcon k="status" /></th>
                <th>Owner</th>
                <th role="button" aria-sort={sortKey === 'firstDetected' ? (sortAsc ? 'ascending' : 'descending') : 'none'} onClick={() => toggleSort('firstDetected')} className="th-sortable" tabIndex={0} onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('firstDetected'))}>Detected <SortIcon k="firstDetected" /></th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {paginated.map(f => (
                <tr key={f.id} className={`finding-tr ${selectedIds.has(f.id) ? 'finding-tr--selected' : ''}`} onClick={() => setSelected(f)} tabIndex={0} onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setSelected(f))}>
                  <td onClick={e => e.stopPropagation()} onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && e.stopPropagation()}>
                    <input type="checkbox"
                      aria-label={`Select finding ${f.title}`}
                      checked={selectedIds.has(f.id)}
                      onChange={(e) => {
                        const next = new Set(selectedIds);
                        if (e.target.checked) next.add(f.id); else next.delete(f.id);
                        setSelectedIds(next);
                      }}
                      style={{ cursor: 'pointer', accentColor: '#38bdf8' }}
                    />
                  </td>
                  <td><SevBadge severity={f.severity} /></td>
                  <td>
                    <div style={{ maxWidth: 280 }}>
                      <div style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.title || f.description.slice(0, 55)}</div>
                      {f.cwe && <div style={{ color: 'var(--color-text-muted)', fontSize: 11, marginTop: 1 }}>{f.cwe}</div>}
                    </div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--color-text-muted)', fontSize: 12 }}>
                      <GitCommit size={11} />
                      <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{f.file.split('/').pop()}:{f.line}</span>
                    </div>
                  </td>
                  <td><span style={{ color: 'var(--color-text-muted)', fontSize: 12 }}>{f.repository.split('/').pop()}</span></td>
                  <td>
                    <span style={{
                      color: VERDICT_CONFIG[f.aiVerdict]?.color || '#94a3b8',
                      background: `${VERDICT_CONFIG[f.aiVerdict]?.color || '#94a3b8'}15`,
                      borderRadius: 4, padding: '1px 6px', fontSize: 11, fontWeight: 600,
                    }}>{f.aiVerdict}</span>
                  </td>
                  <td onClick={e => e.stopPropagation()}>
                    <StatusPill status={f.status} onClick={() => {
                      const statuses = Object.keys(STATUS_CONFIG) as FindingStatus[];
                      const nextIdx = (statuses.indexOf(f.status) + 1) % statuses.length;
                      onStatusChange(f.id, statuses[nextIdx]);
                    }} />
                  </td>
                  <td>
                    <span style={{ color: f.owner ? '#94a3b8' : '#334155', fontSize: 12 }}>
                      {f.owner || '—'}
                    </span>
                  </td>
                  <td><span style={{ color: '#475569', fontSize: 11 }}>{new Date(f.firstDetected).toLocaleDateString()}</span></td>
                  <td><ExternalLink size={13} style={{ color: '#334155' }} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination controls */}
      {totalPages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16, marginTop: 16, flexShrink: 0 }}>
          <button 
            onClick={() => setPage(p => Math.max(1, p - 1))} 
            disabled={page === 1}
            style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: page === 1 ? '#475569' : '#e2e8f0', padding: '6px 12px', borderRadius: 6, fontSize: 12, cursor: page === 1 ? 'not-allowed' : 'pointer' }}
          >Previous</button>
          <span style={{ fontSize: 12, color: '#94a3b8' }}>Page {page} of {totalPages}</span>
          <button 
            onClick={() => setPage(p => Math.min(totalPages, p + 1))} 
            disabled={page === totalPages}
            style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: page === totalPages ? '#475569' : '#e2e8f0', padding: '6px 12px', borderRadius: 6, fontSize: 12, cursor: page === totalPages ? 'not-allowed' : 'pointer' }}
          >Next</button>
        </div>
      )}

      {/* Detail panel */}
      {selected && (
        <FindingDetail
          finding={selected}
          onClose={() => setSelected(null)}
          onStatusChange={(id, s) => { onStatusChange(id, s); setSelected(prev => prev ? { ...prev, status: s } : null); }}
          onOwnerChange={(id, o) => { onOwnerChange(id, o); setSelected(prev => prev ? { ...prev, owner: o } : null); }}
          onRemediationUpdate={(id, r) => { onRemediationUpdate(id, r); setSelected(prev => prev ? { ...prev, remediationSuggestion: r } : null); }}
          onExploitUpdate={(id, v, o, p) => { onExploitUpdate(id, v, o, p); setSelected(prev => prev ? { ...prev, exploitVerified: v, exploitOutput: o, exploitPath: p } : null); }}
        />
      )}
    </div>
  );
}
