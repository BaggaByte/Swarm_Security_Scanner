/**
 * App — Product shell with sidebar navigation and page routing.
 * Phase 1: client-side routing, localStorage persistence.
 */

import React, { useState, useCallback, useEffect } from 'react';
import {
  LayoutDashboard, ShieldAlert, History, Database,
  ScanLine, ChevronLeft, ChevronRight, Settings,
  Zap, X, Menu, Award,
} from 'lucide-react';

import { useStore } from './useStore';
import type { Finding, FindingStatus, Repository, ScanRun } from './types';

const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const FindingsPage = React.lazy(() => import('./pages/FindingsPage'));
const ScanHistoryPage = React.lazy(() => import('./pages/ScanHistoryPage'));
const RepositoriesPage = React.lazy(() => import('./pages/RepositoriesPage'));
const ScanPage = React.lazy(() => import('./pages/ScanPage'));
const ArchitecturePage = React.lazy(() => import('./pages/ArchitecturePage'));
const BenchmarkPage = React.lazy(() => import('./pages/BenchmarkPage'));
const SettingsPage = React.lazy(() => import('./pages/SettingsPage'));

// ── Nav items ──────────────────────────────────────────────────────────────────

type PageId = 'dashboard' | 'architecture' | 'findings' | 'scans' | 'repositories' | 'scan' | 'benchmark' | 'settings';

interface NavItem {
  id: PageId;
  label: string;
  icon: React.ReactNode;
  badge?: (store: ReturnType<typeof useStore>) => number | null;
}

const NAV_ITEMS: NavItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: <LayoutDashboard size={17} />,
  },
  {
    id: 'architecture',
    label: 'Architecture Map',
    icon: <Database size={17} />,
  },
  {
    id: 'findings',
    label: 'Findings',
    icon: <ShieldAlert size={17} />,
    badge: store => {
      const n = store.findings.filter(f => f.status === 'new' && f.aiVerdict === 'TP').length;
      return n > 0 ? n : null;
    },
  },
  {
    id: 'scans',
    label: 'Scan History',
    icon: <History size={17} />,
  },
  {
    id: 'repositories',
    label: 'Repositories',
    icon: <Database size={17} />,
  },
  {
    id: 'scan',
    label: 'New Scan',
    icon: <ScanLine size={17} />,
  },
  {
    id: 'benchmark',
    label: 'CVE Benchmark',
    icon: <Award size={17} />,
  },
  {
    id: 'settings',
    label: 'Settings & Org',
    icon: <Settings size={17} />,
  },
];

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [activePage, setActivePage] = useState<PageId>('dashboard');
  const [collapsed, setCollapsed] = useState(() => window.innerWidth <= 768);
  const [preloadRepo, setPreloadRepo] = useState<string | undefined>();
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');

  const store = useStore();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isSettingsOpen) {
        setIsSettingsOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    
    const mediaQuery = window.matchMedia('(max-width: 768px)');
    const handleMediaChange = (e: MediaQueryListEvent) => setCollapsed(e.matches);
    mediaQuery.addEventListener('change', handleMediaChange);
    
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      mediaQuery.removeEventListener('change', handleMediaChange);
    };
  }, [isSettingsOpen]);

  // Handlers
  const handleNavigate = useCallback((page: string, opts?: { repo?: string }) => {
    if (opts?.repo) setPreloadRepo(opts.repo);
    setActivePage(page as PageId);
  }, []);

  const handleFindingsFound = useCallback((findings: Finding[]) => {
    store.addFindings(findings);
  }, [store]);

  const handleScanRunSaved = useCallback((run: ScanRun) => {
    store.upsertScanRun(run);
  }, [store]);

  const handleRepoAdded = useCallback((repo: Repository) => {
    store.upsertRepository(repo);
  }, [store]);

  const handleScanRepo = useCallback((url: string) => {
    setPreloadRepo(url);
    setActivePage('scan');
  }, []);

  return (
    <div className="app-shell">
      {/* ── Sidebar ── */}
      {window.innerWidth <= 768 && !collapsed && (
        <div 
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 39, backdropFilter: 'blur(2px)' }} 
          onClick={() => setCollapsed(true)} 
        />
      )}
      <aside className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}>
        {/* Logo */}
        <div className="sidebar__logo">
          <div className="sidebar__logo-icon">
            <Zap size={16} />
          </div>
          {!collapsed && (
            <div className="sidebar__logo-text">
              <span className="sidebar__logo-name">Antigravity</span>
              <span className="sidebar__logo-sub">Security Platform</span>
            </div>
          )}
          <button className="sidebar__collapse-btn" onClick={() => setCollapsed(v => !v)} title={collapsed ? 'Expand' : 'Collapse'}>
            {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
          </button>
        </div>

        {/* Nav */}
        <nav className="sidebar__nav">
          {NAV_ITEMS.map(item => {
            const badge = item.badge ? item.badge(store) : null;
            const isActive = activePage === item.id;
            return (
              <button
                key={item.id}
                className={`sidebar__nav-item ${isActive ? 'sidebar__nav-item--active' : ''}`}
                onClick={() => { 
                  setPreloadRepo(undefined); 
                  setActivePage(item.id); 
                  if (window.innerWidth <= 768) setCollapsed(true);
                }}
                title={collapsed ? item.label : undefined}
                aria-current={isActive ? "page" : undefined}
              >
                <span className="sidebar__nav-icon">{item.icon}</span>
                {!collapsed && <span className="sidebar__nav-label">{item.label}</span>}
                {badge != null && <span className="sidebar__nav-badge">{badge > 99 ? '99+' : badge}</span>}
              </button>
            );
          })}
        </nav>

        {/* Bottom items */}
        <div className="sidebar__footer">
          <div className="sidebar__version">
            {!collapsed && <span>v1.0 · Phase 1 <span style={{ color: '#fbbf24', fontSize: 9, fontWeight: 700, letterSpacing: '0.06em' }}>VALIDATE</span></span>}
          </div>
        </div>
      </aside>

      {/* ── Main content ── */}
      <div className="app-content">
        {/* Top bar */}
        <header className="topbar">
          <div className="topbar__breadcrumb">
            <button className="topbar__icon-btn mobile-menu-btn" onClick={() => setCollapsed(false)} aria-label="Open menu" style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 0, display: 'inline-flex', alignItems: 'center', marginRight: 12 }}>
              <Menu size={18} />
            </button>
            <span className="topbar__page-name">
              {NAV_ITEMS.find(n => n.id === activePage)?.label ?? 'Dashboard'}
            </span>
          </div>
          <div className="topbar__actions">
            {/* Running indicator */}
            {store.scanRuns.some(r => r.status === 'running') && (
              <div className="topbar__running-indicator">
                <span className="pulse-dot" style={{ color: '#38bdf8', display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: '#38bdf8', animation: 'pulse-ring 1.5s cubic-bezier(0.4,0,0.6,1) infinite' }} />
                Scan running
              </div>
            )}
            <button className="topbar__icon-btn" title="Settings" onClick={() => setIsSettingsOpen(true)} style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer' }}>
              <Settings size={16} />
            </button>
          </div>
        </header>

        {/* Page content */}
        <main className="page-content">
          <React.Suspense fallback={<div className="page-container" style={{ padding: 32, color: '#94a3b8', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>Loading view...</div>}>
            {activePage === 'dashboard' && (
              <Dashboard
                findings={store.findings}
                scanRuns={store.scanRuns}
                repositories={store.repositories}
                onNavigate={(page) => handleNavigate(page)}
              />
            )}
            {activePage === 'findings' && (
              <FindingsPage
                findings={store.findings}
                onStatusChange={store.updateFindingStatus}
                onOwnerChange={store.updateFindingOwner}
                onRemediationUpdate={store.updateFindingRemediation}
                onExploitUpdate={store.updateFindingExploit}
              />
            )}
            {activePage === 'architecture' && (
              <ArchitecturePage />
            )}
            {activePage === 'scans' && (
              <ScanHistoryPage
                scanRuns={store.scanRuns}
                onNavigate={(page) => handleNavigate(page)}
              />
            )}
            {activePage === 'repositories' && (
              <RepositoriesPage
                repositories={store.repositories}
                onAddRepo={(url) => {
                  const parts = url.replace(/\.git$/, '').split('/');
                  const name = parts[parts.length - 1] || url;
                  store.upsertRepository({
                    id: url,
                    name,
                    url,
                    type: url.includes('github.com') ? 'github' : url.includes('gitlab.com') ? 'gitlab' : 'local',
                    openFindings: store.findings.filter(f => f.repository === url && f.status !== 'false_positive' && f.status !== 'fixed').length,
                    criticalCount: store.findings.filter(f => f.repository === url && f.severity === 'CRITICAL').length,
                    highCount: store.findings.filter(f => f.repository === url && f.severity === 'HIGH').length,
                  });
                }}
                onRemoveRepo={store.removeRepository}
                onScanRepo={handleScanRepo}
              />
            )}
            {activePage === 'scan' && (
              <ScanPage
                preloadRepo={preloadRepo}
                onFindingsFound={handleFindingsFound}
                onScanRunSaved={handleScanRunSaved}
                onRepoAdded={handleRepoAdded}
              />
            )}
            {activePage === 'benchmark' && (
              <BenchmarkPage />
            )}
            {activePage === 'settings' && (
              <SettingsPage />
            )}
          </React.Suspense>
        </main>

      </div>

      {isSettingsOpen && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}>
          <div role="dialog" aria-modal="true" aria-labelledby="settings-title" className="glass" style={{ background: '#0f172a', padding: 24, borderRadius: 12, width: 400, maxWidth: '90%', position: 'relative' }}>
            <button onClick={() => setIsSettingsOpen(false)} style={{ position: 'absolute', top: 16, right: 16, background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer' }} aria-label="Close Settings">
              <X size={16} />
            </button>
            <h2 id="settings-title" style={{ margin: '0 0 16px 0', fontSize: 18, color: '#f8fafc' }}>Settings</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <label style={{ display: 'block', marginBottom: 8, fontSize: 13, color: '#cbd5e1' }}>Swarm API Key</label>
                <input 
                  type="password" 
                  value={store.apiKey} 
                  onChange={e => { store.setApiKey(e.target.value); setTestStatus('idle'); }}
                  placeholder="Enter API Key"
                  style={{ width: '100%', padding: '8px 12px', borderRadius: 6, border: '1px solid #334155', background: '#020617', color: '#f8fafc' }}
                />
                <p style={{ marginTop: 6, fontSize: 11, color: '#64748b' }}>This key is stored locally in your browser and used to authenticate with the Swarm API.</p>
              </div>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <button 
                  onClick={async () => {
                    setTestStatus('testing');
                    try {
                      const API = window.location.origin.includes('5173') ? 'http://127.0.0.1:8001' : '';
                      const res = await fetch(`${API}/api/health/auth`, { headers: { 'Authorization': `Bearer ${store.apiKey}` }});
                      setTestStatus(res.ok ? 'success' : 'error');
                    } catch {
                      setTestStatus('error');
                    }
                  }}
                  className="btn-primary" 
                  style={{ padding: '6px 12px', fontSize: 12 }}
                  disabled={!store.apiKey || testStatus === 'testing'}
                >
                  {testStatus === 'testing' ? 'Testing...' : 'Test Connection'}
                </button>
                <button 
                  onClick={() => { store.setApiKey(''); setTestStatus('idle'); }}
                  style={{ background: 'transparent', border: '1px solid rgba(248,113,113,0.3)', color: '#f87171', padding: '6px 12px', borderRadius: 8, fontSize: 12, cursor: 'pointer' }}
                >
                  Clear Key
                </button>
                {testStatus === 'success' && <span style={{ color: '#34d399', fontSize: 12, fontWeight: 500, marginLeft: 'auto' }}>✓ Connected</span>}
                {testStatus === 'error' && <span style={{ color: '#f87171', fontSize: 12, fontWeight: 500, marginLeft: 'auto' }}>✗ Connection Failed</span>}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
