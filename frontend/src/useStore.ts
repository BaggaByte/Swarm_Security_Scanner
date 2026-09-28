import { useSyncExternalStore, useCallback } from 'react';
import type { Finding, ScanRun, Repository } from './types';

function readLS<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeLS<T>(key: string, value: T) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* quota */ }
}

type StoreState = {
  findings: Finding[];
  scanRuns: ScanRun[];
  repositories: Repository[];
  apiKey: string;
};

let state: StoreState = {
  findings: readLS('ag_findings', []),
  scanRuns: readLS('ag_scan_runs', []),
  repositories: readLS('ag_repos', []),
  apiKey: readLS('ag_api_key', ''),
};

const listeners = new Set<() => void>();

function setState(newState: Partial<StoreState>) {
  state = { ...state, ...newState };
  if ('findings' in newState) writeLS('ag_findings', state.findings);
  if ('scanRuns' in newState) writeLS('ag_scan_runs', state.scanRuns);
  if ('repositories' in newState) writeLS('ag_repos', state.repositories);
  if ('apiKey' in newState) writeLS('ag_api_key', state.apiKey);
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
    const idx = prev.findIndex(x => x.file === f.file && x.line === f.line && x.ruleId === f.ruleId);
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
      const idx = next.findIndex(x => x.file === f.file && x.line === f.line && x.ruleId === f.ruleId);
      if (idx >= 0) {
        next[idx] = { ...next[idx], lastDetected: f.lastDetected, scanId: f.scanId };
      } else {
        next.unshift(f);
      }
    }
    setState({ findings: next });
  }, []);

  const updateFindingStatus = useCallback((id: string, status: Finding['status']) => {
    setState({ findings: state.findings.map(f => f.id === id ? { ...f, status } : f) });
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
