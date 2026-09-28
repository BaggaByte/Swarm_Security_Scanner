/**
 * Repository Management — add, view, and manage monitored repositories.
 */

import React, { useState } from 'react';
import {
  Plus, Trash2, GitBranch, FolderOpen, Globe, AlertOctagon,
  Play, RefreshCw, MoreVertical,
} from 'lucide-react';
import type { Repository } from '../types';

// ── Helpers ────────────────────────────────────────────────────────────────────

function repoType(url: string): Repository['type'] {
  if (url.startsWith('https://github.com')) return 'github';
  if (url.startsWith('https://gitlab.com')) return 'gitlab';
  return 'local';
}

function repoName(url: string): string {
  try {
    const parts = url.replace(/\.git$/, '').split('/');
    return parts[parts.length - 1] || url;
  } catch { return url; }
}

// ── RepoCard ───────────────────────────────────────────────────────────────────

interface RepoCardProps {
  repo: Repository;
  onRemove: (id: string) => void;
  onScan: (url: string) => void;
}

function RepoCard({ repo, onRemove, onScan }: RepoCardProps) {
  const [showMenu, setShowMenu] = useState(false);

  const TypeIcon = repo.type === 'github' ? Globe : repo.type === 'gitlab' ? Globe : FolderOpen;
  const typeColor = repo.type === 'github' ? '#e2e8f0' : repo.type === 'gitlab' ? '#fc6d26' : '#fbbf24';

  return (
    <div className="repo-card">
      <div className="repo-card__header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ background: `${typeColor}15`, color: typeColor, borderRadius: 8, padding: 8, display: 'flex' }}>
            <TypeIcon size={16} />
          </div>
          <div>
            <div style={{ color: '#e2e8f0', fontWeight: 600, fontSize: 14 }}>{repo.name}</div>
            <div style={{ color: '#475569', fontSize: 11, marginTop: 1 }}>{repo.url}</div>
          </div>
        </div>
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setShowMenu(v => !v)}
            style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', padding: 4 }}
          >
            <MoreVertical size={15} />
          </button>
          {showMenu && (
            <div style={{
              position: 'absolute', right: 0, top: '100%', marginTop: 4,
              background: '#0d1726', border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 8, padding: 4, minWidth: 140, zIndex: 100,
            }}>
              <button className="menu-item" onClick={() => { onScan(repo.url); setShowMenu(false); }}>
                <Play size={12} /> Scan now
              </button>
              <button className="menu-item menu-item--danger" onClick={() => { onRemove(repo.id); setShowMenu(false); }}>
                <Trash2 size={12} /> Remove
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'flex', gap: 12, marginTop: 14 }}>
        {repo.criticalCount > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#f87171', fontSize: 12 }}>
            <AlertOctagon size={12} /> {repo.criticalCount} Critical
          </div>
        )}
        {repo.highCount > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#fb923c', fontSize: 12 }}>
            <AlertOctagon size={12} /> {repo.highCount} High
          </div>
        )}
        <div style={{ color: '#475569', fontSize: 12 }}>
          {repo.openFindings} open findings
        </div>
      </div>

      {/* Footer */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 14, paddingTop: 12, borderTop: '1px solid rgba(255,255,255,0.05)' }}>
        <span style={{ color: '#475569', fontSize: 11 }}>
          {repo.lastScanned ? `Last scanned ${new Date(repo.lastScanned).toLocaleDateString()}` : 'Never scanned'}
        </span>
        <button
          onClick={() => onScan(repo.url)}
          style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '5px 12px', borderRadius: 6, background: 'rgba(56,189,248,0.1)', border: '1px solid rgba(56,189,248,0.2)', color: '#38bdf8', fontSize: 12, cursor: 'pointer', transition: 'all 0.15s' }}
        >
          <RefreshCw size={12} /> Scan
        </button>
      </div>
    </div>
  );
}

// ── Main ───────────────────────────────────────────────────────────────────────

interface RepositoriesPageProps {
  repositories: Repository[];
  onAddRepo: (url: string) => void;
  onRemoveRepo: (id: string) => void;
  onScanRepo: (url: string) => void;
}

export default function RepositoriesPage({ repositories, onAddRepo, onRemoveRepo, onScanRepo }: RepositoriesPageProps) {
  const [newUrl, setNewUrl] = useState('');
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState('');

  const handleAdd = () => {
    const url = newUrl.trim();
    if (!url) { setError('Please enter a repository URL or path.'); return; }
    setError('');
    onAddRepo(url);
    setNewUrl('');
    setAdding(false);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Repositories</h1>
          <p className="page-subtitle">{repositories.length} repositories monitored</p>
        </div>
        <button className="btn-primary" onClick={() => setAdding(true)}>
          <Plus size={14} /> Add Repository
        </button>
      </div>

      {/* Add form */}
      {adding && (
        <div className="add-repo-form">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <GitBranch size={16} style={{ color: '#a78bfa' }} />
            <span style={{ color: '#e2e8f0', fontWeight: 600 }}>Add Repository</span>
          </div>
          <p style={{ color: '#475569', fontSize: 13, marginBottom: 12 }}>
            Enter a public GitHub/GitLab URL or a local absolute path.
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              value={newUrl}
              onChange={e => { setNewUrl(e.target.value); setError(''); }}
              onKeyDown={e => e.key === 'Enter' && handleAdd()}
              placeholder="https://github.com/org/repo  or  C:/path/to/project"
              style={{
                flex: 1, padding: '10px 14px', borderRadius: 8,
                background: 'rgba(255,255,255,0.05)', border: `1px solid ${error ? 'rgba(248,113,113,0.5)' : 'rgba(255,255,255,0.1)'}`,
                color: '#e2e8f0', fontSize: 13, fontFamily: 'JetBrains Mono, monospace',
                outline: 'none',
              }}
              autoFocus
            />
            <button className="btn-primary" onClick={handleAdd}>Add</button>
            <button
              onClick={() => { setAdding(false); setNewUrl(''); setError(''); }}
              style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: '#64748b', cursor: 'pointer' }}
            >Cancel</button>
          </div>
          {error && <p style={{ color: '#f87171', fontSize: 12, marginTop: 6 }}>{error}</p>}
        </div>
      )}

      {/* Grid */}
      {repositories.length === 0 ? (
        <div className="empty-full">
          <GitBranch size={40} style={{ color: '#1e293b' }} />
          <p style={{ color: '#475569', fontSize: 14, marginTop: 12 }}>No repositories added yet.</p>
          <button className="btn-primary" style={{ marginTop: 12 }} onClick={() => setAdding(true)}>
            <Plus size={14} /> Add your first repository
          </button>
        </div>
      ) : (
        <div className="repo-grid">
          {repositories.map(r => (
            <RepoCard
              key={r.id}
              repo={r}
              onRemove={onRemoveRepo}
              onScan={onScanRepo}
            />
          ))}
        </div>
      )}
    </div>
  );
}
