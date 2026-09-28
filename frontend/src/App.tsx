/**
 * App — Product shell with sidebar navigation and page routing.
 * Phase 1: client-side routing, localStorage persistence.
 */

import React, { useState, useCallback } from 'react';
import {
  LayoutDashboard, ShieldAlert, History, Database,
  ScanLine, ChevronLeft, ChevronRight, Settings,
  Zap,
} from 'lucide-react';

import { useStore } from './useStore';
import type { Finding, FindingStatus, Repository, ScanRun } from './types';
import Dashboard from './pages/Dashboard';
import FindingsPage from './pages/FindingsPage';
import ScanHistoryPage from './pages/ScanHistoryPage';
import RepositoriesPage from './pages/RepositoriesPage';
import ScanPage from './pages/ScanPage';
import ArchitecturePage from './pages/ArchitecturePage';

// ── Nav items ──────────────────────────────────────────────────────────────────

type PageId = 'dashboard' | 'architecture' | 'findings' | 'scans' | 'repositories' | 'scan';

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
];

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [activePage, setActivePage] = useState<PageId>('dashboard');
  const [collapsed, setCollapsed] = useState(false);
  const [preloadRepo, setPreloadRepo] = useState<string | undefined>();

  const store = useStore();

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
                onClick={() => { setPreloadRepo(undefined); setActivePage(item.id); }}
                title={collapsed ? item.label : undefined}
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
            {!collapsed && <span>v1.0 · Phase 1</span>}
          </div>
        </div>
      </aside>

      {/* ── Main content ── */}
      <div className="app-content">
        {/* Top bar */}
        <header className="topbar">
          <div className="topbar__breadcrumb">
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
            <a href="#" className="topbar__icon-btn" title="Settings">
              <Settings size={16} />
            </a>
          </div>
        </header>

        {/* Page content */}
        <main className="page-content">
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
        </main>
      </div>
    </div>
  );
}
