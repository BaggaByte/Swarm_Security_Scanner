import { useSyncExternalStore, useCallback } from 'react';
import type { Finding, ScanRun, Repository } from './types';

type StoreState = {
  findings: Finding[];
  scanRuns: ScanRun[];
  repositories: Repository[];
  apiKey: string;
};

function readSessionApiKey(): string {
  try {
    const key = sessionStorage.getItem('ag_api_key') || '';
    // Remove the older persistent copy after migrating it into this tab's session.
    const legacy = localStorage.getItem('ag_api_key');
    if (!key && legacy) sessionStorage.setItem('ag_api_key', JSON.parse(legacy));
    localStorage.removeItem('ag_api_key');
    return key || (legacy ? JSON.parse(legacy) : '');
  } catch {
    try { localStorage.removeItem('ag_api_key'); } catch { /* storage unavailable */ }
    return '';
  }
}

function writeSessionApiKey(value: string) {
  try {
    if (value) sessionStorage.setItem('ag_api_key', value);
    else sessionStorage.removeItem('ag_api_key');
    localStorage.removeItem('ag_api_key');
  } catch { /* storage unavailable */ }
}

let state: StoreState = {
  findings: [],
  scanRuns: [],
  repositories: [],
  apiKey: readSessionApiKey(),
};

let isSynced = false;

const listeners = new Set<() => void>();

function fetchState() {
  if (!state.apiKey) return;
  const headers = { Authorization: `Bearer ${state.apiKey}` };
  const api = window.location.origin.includes('5173') ? 'http://127.0.0.1:8001' : '';
  Promise.all([
    fetch(`${api}/api/findings`, { headers }).then(r => r.ok ? r.json() : []),
    fetch(`${api}/api/repositories`, { headers }).then(r => r.ok ? r.json() : []),
    fetch(`${api}/api/frontend_runs`, { headers }).then(r => r.ok ? r.json() : [])
  ]).then(([findings, repos, runs]) => {
    state = { ...state, findings, repositories: repos, scanRuns: runs };
    isSynced = true;
    listeners.forEach(l => l());
  }).catch(() => {});
}

fetchState();

function setState(newState: Partial<StoreState>) {
  state = { ...state, ...newState };
  if ('apiKey' in newState) {
    writeSessionApiKey(state.apiKey);
    fetchState();
  } else if (isSynced && state.apiKey) {
    const api = window.location.origin.includes('5173') ? 'http://127.0.0.1:8001' : '';
    const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${state.apiKey}` };
    if ('findings' in newState) {
      fetch(`${api}/api/findings`, { method: 'POST', headers, body: JSON.stringify(state.findings) });
    }
    if ('repositories' in newState) {
      fetch(`${api}/api/repositories`, { method: 'POST', headers, body: JSON.stringify(state.repositories) });
    }
    if ('scanRuns' in newState) {
      fetch(`${api}/api/frontend_runs`, { method: 'POST', headers, body: JSON.stringify(state.scanRuns) });
    }
  }
  listeners.forEach(l => l());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function getSnapshot() {
  return state;
}

export function useStore() {
  const store = useSyncExternalStore(subscribe, getSnapshot);

  const addFinding = useCallback((f: Finding) => {
    const prev = state.findings;
    const idx = prev.findIndex(x => x.repository === f.repository && x.file === f.file && x.line === f.line && x.ruleId === f.ruleId);
    if (idx >= 0) {
      const updated = [...prev];
      updated[idx] = { ...updated[idx], lastDetected: f.lastDetected, scanId: f.scanId };
      setState({ findings: updated });
    } else {
      setState({ findings: [f, ...prev] });
    }
  }, []);

  const addFindings = useCallback((fs: Finding[]) => {
    const next = [...state.findings];
    for (const f of fs) {
      const idx = next.findIndex(x => x.repository === f.repository && x.file === f.file && x.line === f.line && x.ruleId === f.ruleId);
      if (idx >= 0) {
        next[idx] = { ...next[idx], lastDetected: f.lastDetected, scanId: f.scanId };
      } else {
        next.unshift(f);
      }
    }
    setState({ findings: next });
  }, []);

  const updateFindingStatus = useCallback((id: string, status: Finding['status']) => {
    setState({ findings: state.findings.map(f => {
      if (f.id === id) {
        const updates: Partial<Finding> = { status };
        if (status === 'fixed' && f.status !== 'fixed') updates.fixedAt = Date.now();
        else if (status !== 'fixed') updates.fixedAt = undefined;
        return { ...f, ...updates };
      }
      return f;
    }) });
  }, []);

  const updateFindingOwner = useCallback((id: string, owner: string) => {
    setState({ findings: state.findings.map(f => f.id === id ? { ...f, owner } : f) });
  }, []);

  const updateFindingRemediation = useCallback((id: string, remediation: string) => {
    setState({ findings: state.findings.map(f => f.id === id ? { ...f, remediationSuggestion: remediation } : f) });
  }, []);

  const updateFindingExploit = useCallback((id: string, verified: boolean, output: string, exploitPath: string) => {
    setState({ findings: state.findings.map(f => f.id === id ? { ...f, exploitVerified: verified, exploitOutput: output, exploitPath: exploitPath } : f) });
  }, []);

  const upsertScanRun = useCallback((run: ScanRun) => {
    const prev = state.scanRuns;
    const idx = prev.findIndex(r => r.id === run.id);
    if (idx >= 0) {
      const updated = [...prev];
      updated[idx] = run;
      setState({ scanRuns: updated });
    } else {
      setState({ scanRuns: [run, ...prev] });
    }
  }, []);

  const upsertRepository = useCallback((repo: Repository) => {
    const prev = state.repositories;
    const idx = prev.findIndex(r => r.url === repo.url);
    if (idx >= 0) {
      const updated = [...prev];
      updated[idx] = { ...updated[idx], ...repo };
      setState({ repositories: updated });
    } else {
      setState({ repositories: [repo, ...prev] });
    }
  }, []);

  const removeRepository = useCallback((id: string) => {
    setState({ repositories: state.repositories.filter(r => r.id !== id) });
  }, []);
  
  const setApiKey = useCallback((key: string) => {
    setState({ apiKey: key });
  }, []);

  return {
    ...store,
    addFinding,
    addFindings,
    updateFindingStatus,
    updateFindingOwner,
    updateFindingRemediation,
    updateFindingExploit,
    upsertScanRun,
    upsertRepository,
    removeRepository,
    setApiKey,
  };
}
