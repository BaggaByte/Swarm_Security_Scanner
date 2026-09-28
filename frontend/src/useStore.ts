/**
 * useStore — lightweight client-side persistence via localStorage.
 * Manages: findings, scan history, repositories.
 *
 * In Phase 2 these will be replaced by API calls to the backend.
 */

import { useState, useEffect, useCallback } from 'react';
import type { Finding, ScanRun, Repository } from './types';

// ── Helpers ───────────────────────────────────────────────────────────────────

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

// ── Store hook ────────────────────────────────────────────────────────────────

export function useStore() {
  const [findings, setFindings] = useState<Finding[]>(() => readLS('ag_findings', []));
  const [scanRuns, setScanRuns] = useState<ScanRun[]>(() => readLS('ag_scan_runs', []));
  const [repositories, setRepositories] = useState<Repository[]>(() => readLS('ag_repos', []));

  // Persist on change
  useEffect(() => writeLS('ag_findings', findings), [findings]);
  useEffect(() => writeLS('ag_scan_runs', scanRuns), [scanRuns]);
  useEffect(() => writeLS('ag_repos', repositories), [repositories]);

  // ── Findings ────────────────────────────────────────────────────────────────

  const addFinding = useCallback((f: Finding) => {
    setFindings(prev => {
      const idx = prev.findIndex(x => x.file === f.file && x.line === f.line && x.ruleId === f.ruleId);
      if (idx >= 0) {
        const updated = [...prev];
        updated[idx] = { ...updated[idx], lastDetected: f.lastDetected, scanId: f.scanId };
        return updated;
      }
      return [f, ...prev];
    });
  }, []);

  const addFindings = useCallback((fs: Finding[]) => {
    setFindings(prev => {
      const next = [...prev];
      for (const f of fs) {
        const idx = next.findIndex(x => x.file === f.file && x.line === f.line && x.ruleId === f.ruleId);
        if (idx >= 0) {
          next[idx] = { ...next[idx], lastDetected: f.lastDetected, scanId: f.scanId };
        } else {
          next.unshift(f);
        }
      }
      return next;
    });
  }, []);

  const updateFindingStatus = useCallback((id: string, status: Finding['status']) => {
    setFindings(prev => prev.map(f => f.id === id ? { ...f, status } : f));
  }, []);

  const updateFindingOwner = useCallback((id: string, owner: string) => {
    setFindings(prev => prev.map(f => f.id === id ? { ...f, owner } : f));
  }, []);

  const updateFindingRemediation = useCallback((id: string, remediation: string) => {
    setFindings(prev => prev.map(f => f.id === id ? { ...f, remediationSuggestion: remediation } : f));
  }, []);

  const updateFindingExploit = useCallback((id: string, verified: boolean, output: string, exploitPath: string) => {
    setFindings(prev => prev.map(f => f.id === id ? { ...f, exploitVerified: verified, exploitOutput: output, exploitPath: exploitPath } : f));
  }, []);

  // ── Scan Runs ────────────────────────────────────────────────────────────────

  const upsertScanRun = useCallback((run: ScanRun) => {
    setScanRuns(prev => {
      const idx = prev.findIndex(r => r.id === run.id);
      if (idx >= 0) {
        const updated = [...prev];
        updated[idx] = run;
        return updated;
      }
      return [run, ...prev];
    });
  }, []);

  // ── Repositories ──────────────────────────────────────────────────────────────

  const upsertRepository = useCallback((repo: Repository) => {
    setRepositories(prev => {
      const idx = prev.findIndex(r => r.url === repo.url);
      if (idx >= 0) {
        const updated = [...prev];
        updated[idx] = { ...updated[idx], ...repo };
        return updated;
      }
      return [repo, ...prev];
    });
  }, []);

  const removeRepository = useCallback((id: string) => {
    setRepositories(prev => prev.filter(r => r.id !== id));
  }, []);

  return {
    findings,
    scanRuns,
    repositories,
    addFinding,
    addFindings,
    updateFindingStatus,
    updateFindingOwner,
    updateFindingRemediation,
    updateFindingExploit,
    upsertScanRun,
    upsertRepository,
    removeRepository,
  };
}
