/**
 * ScanPage — Live scanning console (sandbox + repo modes).
 * Wraps the existing SwarmGraph + LogFeed logic from the original App.tsx
 * and exposes callbacks so findings can be saved to the product store.
 */

import React, {
  useState, useEffect, useRef, useCallback, useMemo,
} from 'react';
import {
  ReactFlow, Background, Controls, MiniMap,
  addEdge, useNodesState, useEdgesState,
  type Node, type Edge, type Connection,
  BackgroundVariant,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Play, TerminalSquare, Share2, Brain, Settings, ChevronDown, ChevronRight } from 'lucide-react';
import type {
  LogEntry, LogType, SandboxScanConfig, RepoScanConfig,
  TriageFinding, Finding, ScanRun, Repository,
} from '../types';
import { useStore } from '../useStore';

// ── Constants ─────────────────────────────────────────────────────────────────

const API = window.location.origin.includes('5173') ? 'http://127.0.0.1:8000' : '';

const LOG_TYPE_ICON: Record<LogType, string> = {
  PHASE: '⬡', WORKER: '◈', CHALLENGER: '⚔', VERDICT: '◎',
  SYSTEM: '·', ERROR: '✗', DONE: '✓',
};

const CYCLE_OPTIONS = ['11', '13a', '13b', '14', '15', '16', '17', '18', '19', '20', '21', '22'];

const DEFAULT_SANDBOX: SandboxScanConfig = {
  model: 'llama3.2',
  challengerModel: 'qwen2.5-coder:7b',
  cycle: '22',
  workers: 5,
  challengers: 2,
};

const DEFAULT_REPO: RepoScanConfig = {
  repo: '',
  model: 'llama3.2',
  challengerModel: 'qwen2.5-coder:7b',
  workers: 5,
  challengers: 2,
  sastTools: ['bandit', 'semgrep'],
  noSast: false,
  maxChunks: 20,
};

const MODEL_PRESETS = [
  { id: 'llama3.2', label: 'Llama 3.2 (Local Ollama)' },
  { id: 'qwen2.5-coder:7b', label: 'Qwen 2.5 Coder 7B (Local Ollama)' },
  { id: 'groq/llama-3.1-8b-instant', label: 'Llama 3.1 8B (Groq)' },
  { id: 'groq/llama3-8b-8192', label: 'Llama 3 8B (Groq)' },
  { id: 'groq/llama-3.2-11b-vision-preview', label: 'Llama 3.2 11B (Groq)' },
];
const CUSTOM_MODEL = '__custom_model__';

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#fbbf24', LOW: '#a3e635', INFO: '#94a3b8',
};

// ── Node graph helpers ────────────────────────────────────────────────────────

function nodeStyle(accent: string) {
  return {
    background: 'rgba(13,23,38,0.65)',
    backdropFilter: 'blur(12px)',
    WebkitBackdropFilter: 'blur(12px)',
    border: `1px solid ${accent}66`,
    borderRadius: '12px',
    color: '#f8fafc',
    fontFamily: 'Inter, sans-serif',
    fontSize: '12px',
    fontWeight: 600,
    padding: '10px 16px',
    boxShadow: `0 8px 24px rgba(0,0,0,0.2), 0 0 16px ${accent}22`,
    minWidth: 130,
    textAlign: 'center' as const,
    transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
  };
}

function activeNodeStyle(accent: string) {
  return {
    ...nodeStyle(accent),
    background: 'rgba(13,23,38,0.85)',
    border: `1.5px solid ${accent}`,
    boxShadow: `0 8px 32px rgba(0,0,0,0.3), 0 0 24px ${accent}66`,
    transform: 'scale(1.05)',
    color: '#ffffff',
  };
}

function buildNodes(workers: number, challengers: number): Node[] {
  const nodes: Node[] = [{
    id: 'orchestrator', type: 'default',
    data: { label: '🔧 Orchestrator' },
    position: { x: 400, y: 40 },
    style: nodeStyle('#0ea5e9'),
  }];
  for (let i = 0; i < workers; i++) {
    nodes.push({ id: `worker-${i}`, type: 'default', data: { label: `⬡ Worker ${i + 1}` }, position: { x: 80 + i * 160, y: 180 }, style: nodeStyle('#84cc16') });
  }
  for (let i = 0; i < challengers; i++) {
    nodes.push({ id: `challenger-${i}`, type: 'default', data: { label: `⚔ Challenger ${i + 1}` }, position: { x: 240 + i * 200, y: 340 }, style: nodeStyle('#f97316') });
  }
  nodes.push({ id: 'verdict', type: 'default', data: { label: '◎ Verdict Engine' }, position: { x: 340, y: 480 }, style: nodeStyle('#a855f7') });
  return nodes;
}

function buildEdges(workers: number, challengers: number): Edge[] {
  const edges: Edge[] = [];
  for (let i = 0; i < workers; i++) edges.push({ id: `e-o-w${i}`, source: 'orchestrator', target: `worker-${i}`, animated: false });
  for (let i = 0; i < workers; i++) for (let c = 0; c < challengers; c++) edges.push({ id: `e-w${i}-c${c}`, source: `worker-${i}`, target: `challenger-${c}`, animated: false });
  for (let i = 0; i < challengers; i++) edges.push({ id: `e-c${i}-v`, source: `challenger-${i}`, target: 'verdict', animated: false });
  return edges;
}

function parseLine(raw: string): LogEntry | null {
  const line = raw.trim();
  if (!line || line.startsWith(':')) return null;
  try {
    const obj = JSON.parse(line);
    return { id: Date.now() + Math.random(), type: (obj.type || 'SYSTEM') as LogType, agent: obj.agent || 'system', content: obj.content || line, ts: Date.now(), finding: obj.finding, verdict: obj.verdict, rationale: obj.rationale, metrics: obj.metrics, scanStatus: obj.scan_status };
  } catch {
    return { id: Date.now() + Math.random(), type: 'SYSTEM', agent: 'runner', content: line, ts: Date.now() };
  }
}

function sourceScopeLabel(finding?: Record<string, unknown>) {
  if (finding?.source_scope === 'benchmark_fixture') return '[Benchmark fixture] ';
  if (finding?.source_scope === 'test_fixture') return '[Test fixture] ';
  return '';
}

// ── Parse triage from SSE logs ─────────────────────────────────────────────

function extractFindings(logs: LogEntry[], scanId: string, repo: string): Finding[] {
  const results: Finding[] = [];
  for (const log of logs) {
    if (log.type === 'VERDICT' && log.agent === 'triage') {
      if (log.finding) {
        results.push({
          id: `${scanId}-${log.finding.id || Math.random()}`,
          repository: repo || 'sandbox',
          file: log.finding.file || 'Unknown',
          line: log.finding.line || 0,
          title: `${sourceScopeLabel(log.finding)}${log.finding.message || 'Finding'}`,
          description: log.rationale || log.content,
          severity: log.finding.severity || 'MEDIUM',
          cwe: null,
          owasp: null,
          status: log.verdict === 'FP' ? 'false_positive' : 'new',
          aiVerdict: ['TP', 'FP', 'INCONCLUSIVE', 'PENDING'].includes(log.verdict as string) ? (log.verdict as any) : 'PENDING',
          swarmRationale: log.rationale || '',
          codeSnippet: log.finding.code || log.finding.snippet || undefined,
          tool: log.finding.tool || 'sast',
          ruleId: log.finding.rule_id || '',
          firstDetected: Date.now(),
          lastDetected: Date.now(),
          scanId,
        });
      }
    }
  }
  return results;
}

function extractMetrics(logs: LogEntry[]) {
  const m: Record<string, number> = {};
  for (const log of logs) {
    if (log.agent === 'metrics') {
      const extract = (label: string) => {
        const match = log.content.match(new RegExp(`${label}[:\\s]+([\\d.]+)`));
        return match ? parseFloat(match[1]) : undefined;
      };
      if (log.content.includes('SAST Findings:')) m.sastFindingCount = extract('SAST Findings') ?? m.sastFindingCount;
      if (log.content.includes('Duration:')) m.durationSeconds = extract('Duration') ?? m.durationSeconds;
      if (log.content.includes('Tokens')) m.tokensEstimated = extract('Tokens') ?? m.tokensEstimated;
      const fpRateMatch = log.content.match(/FP Reduction Rate:\s+([\d.]+)%/);
      if (fpRateMatch) m.fpReductionRate = parseFloat(fpRateMatch[1]);
    }
  }
  return m;
}

function ModelSelector({
  label,
  description,
  value,
  models,
  modelsStatus,
  disabled,
  onChange,
}: {
  label: string;
  description: string;
  value: string;
  models: string[];
  modelsStatus: 'loading' | 'ready' | 'unavailable' | 'no_key';
  disabled: boolean;
  onChange: (model: string) => void;
}) {
  const recommended = new Set(MODEL_PRESETS.map(model => model.id));
  const isCustom = value !== '' && !recommended.has(value) && !models.includes(value);
  const selectValue = isCustom || value === '' ? CUSTOM_MODEL : value;
  const installedModels = Array.from(new Set(models)).sort((a, b) => a.localeCompare(b));
  const isInstalled = (model: string) => models.includes(model) || models.includes(`${model}:latest`);

  return (
    <div className="scan-field">
      <label className="scan-label">{label}</label>
      <select
        className="scan-input"
        value={selectValue}
        onChange={event => onChange(event.target.value === CUSTOM_MODEL ? '' : event.target.value)}
        disabled={disabled}
      >
        {installedModels.length > 0 && (
          <optgroup label="Installed in Ollama">
            {installedModels.map(model => <option key={model} value={model}>{model}</option>)}
          </optgroup>
        )}
        <optgroup label="Recommended models">
          {MODEL_PRESETS.map(model => (
            <option key={model.id} value={model.id}>
              {model.label}{isInstalled(model.id) ? '' : ' · install if needed'}
            </option>
          ))}
        </optgroup>
        {isCustom && <option value={value}>Current custom model · {value}</option>}
        <option value={CUSTOM_MODEL}>Enter a custom model name…</option>
      </select>
      {value.startsWith('groq/') && (
        <p className="scan-model-help" role="note">
          Hosted model selected: repository code and prompts will be sent to Groq.
        </p>
      )}
      {(isCustom || value === '') && (
        <input
          className="scan-input"
          type="text"
          value={value}
          onChange={event => onChange(event.target.value)}
          placeholder="Ollama model name, e.g. my-model:latest"
          disabled={disabled}
          aria-label={`${label} custom Ollama model name`}
          style={{ marginTop: 8 }}
        />
      )}
      <p className="scan-model-help">{description}</p>
      {modelsStatus === 'loading' && <p className="scan-model-help">Loading models installed in Ollama…</p>}
      {modelsStatus === 'ready' && models.length === 0 && (
        <p className="scan-model-help">No installed models found. Choose a recommendation and install it in Ollama before scanning.</p>
      )}
      {modelsStatus === 'unavailable' && (
        <p className="scan-model-help">Could not reach Ollama to list installed models. You can still choose a recommendation or enter a custom model.</p>
      )}
      {modelsStatus === 'no_key' && (
        <p className="scan-model-help">Add your API key in Settings to load the models installed in Ollama.</p>
      )}
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

interface ScanPageProps {
  preloadRepo?: string;
  onFindingsFound: (findings: Finding[]) => void;
  onScanRunSaved: (run: ScanRun) => void;
  onRepoAdded: (repo: Repository) => void;
}

export default function ScanPage({ preloadRepo, onFindingsFound, onScanRunSaved, onRepoAdded }: ScanPageProps) {
  const [scanMode, setScanMode] = useState<'sandbox' | 'repo'>(preloadRepo ? 'repo' : 'sandbox');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [sandboxConfig, setSandboxConfig] = useState<SandboxScanConfig>(DEFAULT_SANDBOX);
  const [repoConfig, setRepoConfig] = useState<RepoScanConfig>({ ...DEFAULT_REPO, repo: preloadRepo || '' });

  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [runId, setRunId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'graph' | 'logs' | 'triage'>('graph');
  const [scanStartTime, setScanStartTime] = useState<number | null>(null);
  const [elapsedTime, setElapsedTime] = useState(0);
  const [streamStatus, setStreamStatus] = useState<'idle' | 'connected' | 'error'>('idle');
  const { apiKey } = useStore();
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [modelsStatus, setModelsStatus] = useState<'loading' | 'ready' | 'unavailable' | 'no_key'>('loading');

  useEffect(() => {
    if (!apiKey) {
      setAvailableModels([]);
      setModelsStatus('no_key');
      return;
    }

    const controller = new AbortController();
    setModelsStatus('loading');
    fetch(`${API}/api/models`, {
      headers: { 'Authorization': `Bearer ${apiKey}` },
      signal: controller.signal,
    })
      .then(async response => {
        if (!response.ok) throw new Error('Model list request failed');
        return response.json();
      })
      .then(data => {
        setAvailableModels(Array.isArray(data.models) ? data.models.filter((model: unknown): model is string => typeof model === 'string') : []);
        setModelsStatus('ready');
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setAvailableModels([]);
          setModelsStatus('unavailable');
        }
      });

    return () => controller.abort();
  }, [apiKey]);

  useEffect(() => {
    let interval: number;
    if (running && scanStartTime) {
      interval = window.setInterval(() => {
        setElapsedTime(Math.floor((Date.now() - scanStartTime) / 1000));
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [running, scanStartTime]);

  useEffect(() => {
    if (!apiKey) return;
    fetch(`${API}/api/scan/active`, { headers: { 'Authorization': `Bearer ${apiKey}` } })
      .then(r => r.json())
      .then(data => {
        if (data && data.length > 0) {
          const active = data.find((r: any) => r.status === 'running');
          if (active) {
            setRunId(active.run_id);
            setRunning(true);
            setScanStartTime(active.started_at ? new Date(active.started_at).getTime() : Date.now());
            // Wait a tick for ref/state to settle before subscribing
            setTimeout(() => subscribeToRunDep(active.run_id, active.scan_type === 'real_world' ? active.repo : 'sandbox'), 100);
          }
        }
      })
      .catch(() => {});
  }, [apiKey]);

  const logEndRef = useRef<HTMLDivElement>(null);
  const esRef = useRef<EventSource | null>(null);

  const [nodes, setNodes, onNodesChange] = useNodesState(buildNodes(sandboxConfig.workers, sandboxConfig.challengers));
  const [edges, setEdges, onEdgesChange] = useEdgesState(buildEdges(sandboxConfig.workers, sandboxConfig.challengers));
  const onConnect = useCallback((conn: Connection) => setEdges(eds => addEdge(conn, eds)), [setEdges]);

  useEffect(() => {
    if (!running) {
      setNodes(buildNodes(sandboxConfig.workers, sandboxConfig.challengers));
      setEdges(buildEdges(sandboxConfig.workers, sandboxConfig.challengers));
    }
  }, [sandboxConfig.workers, sandboxConfig.challengers, running, setNodes, setEdges]);

  useEffect(() => { logEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs]);

  const subscribeToRun = useCallback((id: string, repo: string) => {
    if (esRef.current) esRef.current.close();
    const es = new EventSource(`${API}/api/scan/${id}/stream?token=${encodeURIComponent(apiKey)}`);
    esRef.current = es;

    es.onopen = () => setStreamStatus('connected');
    es.onerror = () => setStreamStatus('error');

    es.onmessage = (event) => {
      const entry = parseLine(event.data);
      if (!entry) return;
      setLogs(prev => [...prev.slice(-1999), entry]);

      // Animate graph nodes
      if (entry.type === 'WORKER') {
        const idx = parseInt(entry.agent.replace(/\D/g, '')) || 0;
        const nid = `worker-${idx % sandboxConfig.workers}`;
        setNodes(nds => nds.map(n => n.id === nid ? { ...n, style: activeNodeStyle('#84cc16') } : n));
        setTimeout(() => setNodes(nds => nds.map(n => n.id === nid ? { ...n, style: nodeStyle('#84cc16') } : n)), 2000);
      }
      if (entry.type === 'CHALLENGER') {
        const idx = parseInt(entry.agent.replace(/\D/g, '')) || 0;
        const nid = `challenger-${idx % sandboxConfig.challengers}`;
        setNodes(nds => nds.map(n => n.id === nid ? { ...n, style: activeNodeStyle('#f97316') } : n));
        setTimeout(() => setNodes(nds => nds.map(n => n.id === nid ? { ...n, style: nodeStyle('#f97316') } : n)), 2000);
      }
      if (entry.type === 'VERDICT') {
        setNodes(nds => nds.map(n => n.id === 'verdict' ? { ...n, style: activeNodeStyle('#a855f7') } : n));
        setTimeout(() => setNodes(nds => nds.map(n => n.id === 'verdict' ? { ...n, style: nodeStyle('#a855f7') } : n)), 2000);
      }
      if (entry.type === 'PHASE') {
        setNodes(nds => nds.map(n => n.id === 'orchestrator' ? { ...n, data: { label: `🔧 ${entry.content.slice(0, 28)}` }, style: activeNodeStyle('#0ea5e9') } : n));
      }

      if (entry.type === 'DONE' || entry.type === 'ERROR') {
        es.close();
        setRunning(false);
        setStreamStatus('idle');
        // extract and save findings
        setLogs(prev => {
          const allLogs = [...prev, entry];
          const findings = extractFindings(allLogs, id, repo);
          const rawMetrics = extractMetrics(allLogs);
          if (findings.length > 0) onFindingsFound(findings);

          const run: ScanRun = {
            id,
            type: scanMode,
            repository: repo || undefined,
            status: (entry.type === 'ERROR' || (entry.type === 'DONE' && (entry as any).exit_code !== 0))
              ? 'error' : entry.scanStatus === 'partial' ? 'partial' : 'done',
            startedAt: Date.now() - (rawMetrics.durationSeconds || 0) * 1000,
            finishedAt: Date.now(),
            model: scanMode === 'sandbox' ? sandboxConfig.model : repoConfig.model,
            challengerModel: scanMode === 'sandbox' ? sandboxConfig.challengerModel : repoConfig.challengerModel,
            workers: scanMode === 'sandbox' ? sandboxConfig.workers : repoConfig.workers,
            challengers: scanMode === 'sandbox' ? sandboxConfig.challengers : repoConfig.challengers,
            findingCount: findings.length,
            confirmedCount: findings.filter(f => f.aiVerdict === 'TP').length,
            fpCount: findings.filter(f => f.aiVerdict === 'FP').length,
            metrics: rawMetrics.durationSeconds ? {
              durationSeconds: rawMetrics.durationSeconds,
              tokensEstimated: rawMetrics.tokensEstimated || 0,
              sastFindingCount: rawMetrics.sastFindingCount || 0,
              swarmConfirmed: findings.filter(f => f.aiVerdict === 'TP').length,
              fpReductionRate: rawMetrics.fpReductionRate || 0,
            } : undefined,
          };
          onScanRunSaved(run);

          // Also register the repo if not already done
          if (repo && (repo.startsWith('http') || repo.startsWith('/'))) {
            const parts = repo.replace(/\.git$/, '').split('/');
            const name = parts[parts.length - 1] || repo;
            onRepoAdded({
              id: repo,
              name,
              url: repo,
              type: repo.includes('github.com') ? 'github' : repo.includes('gitlab.com') ? 'gitlab' : 'local',
              lastScanned: Date.now(),
              openFindings: findings.filter(f => f.status === 'new').length,
              criticalCount: findings.filter(f => f.severity === 'CRITICAL').length,
              highCount: findings.filter(f => f.severity === 'HIGH').length,
            });
          }
          return allLogs;
        });
      }
    };

    es.onerror = () => { 
      // Do not close immediately; let EventSource attempt to reconnect
      console.warn("EventSource disconnected or errored, attempting to reconnect...");
    };
  }, [sandboxConfig, repoConfig, scanMode, onFindingsFound, onScanRunSaved, onRepoAdded, setNodes]);

  const subscribeToRunDep = useCallback(subscribeToRun, [apiKey, setNodes, setRunning, setLogs, onFindingsFound, onScanRunSaved, onRepoAdded]);

  const startSandboxScan = async () => {
    setRunning(true); setLogs([]); setRunId(null);
    setScanStartTime(Date.now());
    setElapsedTime(0);
    setStreamStatus('idle');
    try {
      const res = await fetch(`${API}/api/scan`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({
          model: sandboxConfig.model,
          challenger_model: sandboxConfig.challengerModel,
          cycle: sandboxConfig.cycle,
          workers: sandboxConfig.workers,
          challengers: sandboxConfig.challengers,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setLogs([{ id: Date.now(), type: 'ERROR', agent: 'ui', content: `Failed: ${err.detail || res.statusText}`, ts: Date.now() }]);
        setRunning(false);
        return;
      }
      const data = await res.json();
      setRunId(data.run_id);
      subscribeToRun(data.run_id, 'sandbox');
    } catch (err) {
      setLogs([{ id: 1, type: 'ERROR', agent: 'ui', content: `Failed: ${err}`, ts: Date.now() }]);
      setRunning(false);
    }
  };

  const startRepoScan = async () => {
    if (!repoConfig.repo.trim()) return;
    setRunning(true); setLogs([]); setRunId(null);
    setScanStartTime(Date.now());
    setElapsedTime(0);
    setStreamStatus('idle');
    try {
      const res = await fetch(`${API}/api/repo-scan`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({
          repo: repoConfig.repo,
          model: repoConfig.model,
          challenger_model: repoConfig.challengerModel,
          workers: repoConfig.workers,
          challengers: repoConfig.challengers,
          sast_tools: repoConfig.sastTools,
          no_sast: repoConfig.noSast,
          max_chunks: repoConfig.maxChunks,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setLogs([{ id: Date.now(), type: 'ERROR', agent: 'ui', content: `Failed: ${err.detail || res.statusText}`, ts: Date.now() }]);
        setRunning(false);
        return;
      }
      const data = await res.json();
      setRunId(data.run_id);
      subscribeToRun(data.run_id, repoConfig.repo);
    } catch (err) {
      setLogs([{ id: 1, type: 'ERROR', agent: 'ui', content: `Failed: ${err}`, ts: Date.now() }]);
      setRunning(false);
    }
  };

  // Parse triage findings from log for triage tab
  const triageFindings = useMemo<TriageFinding[]>(() => {
    const findingsMap = new Map<string, TriageFinding>();
    logs
      .filter(l => l.type === 'VERDICT' && l.agent === 'triage')
      .forEach(log => {
        const triage = log.verdict === 'TP' ? 'TP'
          : log.verdict === 'FP' ? 'FP'
          : log.verdict === 'INCONCLUSIVE' ? 'INCONCLUSIVE' : 'PENDING';
        
        const findingId = log.finding?.id || `${log.finding?.file || '?'}:${log.finding?.line || '0'}`;
        
        findingsMap.set(findingId, {
          tool: log.finding?.tool || 'sast', ruleId: log.finding?.rule_id || '', ruleName: '',
          file: log.finding?.file || '?', line: log.finding?.line || 0,
          severity: log.finding?.severity || 'UNKNOWN', confidence: '',
          cwe: null, message: `${sourceScopeLabel(log.finding)}${log.finding?.message || log.content}`, code: log.finding?.code || '',
          triage: triage,
          triageRationale: log.rationale || '',
        });
      });
    return Array.from(findingsMap.values());
  }, [logs]);

  const liveStats = useMemo(() => {
    const verdicts = triageFindings.filter(f => f.triage !== 'PENDING').length;
    const confirmed = triageFindings.filter(f => f.triage === 'TP').length;
    const refuted = triageFindings.filter(f => f.triage === 'FP').length;
    return { findings: triageFindings.length, verdicts, confirmed, refuted };
  }, [triageFindings]);

  const inputCls = 'scan-input';

  return (
    <div className="scan-page">
      {/* Mode tabs */}
      <div className="scan-mode-tabs">
        <button
          className={`scan-mode-tab ${scanMode === 'sandbox' ? 'scan-mode-tab--active' : ''}`}
          onClick={() => setScanMode('sandbox')}
        >
          <span>◈ Sandbox Mode</span>
        </button>
        <button
          className={`scan-mode-tab ${scanMode === 'repo' ? 'scan-mode-tab--active' : ''}`}
          onClick={() => setScanMode('repo')}
        >
          <span>⬡ Real-World Repository</span>
        </button>
      </div>

      <div className="scan-layout">
        {/* ── Sidebar ── */}
        <aside className="scan-sidebar">
          <div className="scan-sidebar__section">
            <h3 className="scan-sidebar__heading">
              {scanMode === 'sandbox' ? 'Sandbox Configuration' : 'Repository Target'}
            </h3>


            {scanMode === 'repo' && (
              <div className="scan-field">
                <label className="scan-label">Git URL or Local Path</label>
                <input
                  className={inputCls}
                  type="text"
                  value={repoConfig.repo}
                  onChange={e => setRepoConfig(c => ({ ...c, repo: e.target.value }))}
                  placeholder="https://github.com/org/repo"
                  disabled={running}
                />
              </div>
            )}

            {scanMode === 'sandbox' && (
              <div className="scan-field">
                <label className="scan-label">Cycle</label>
                <select className={inputCls} value={sandboxConfig.cycle} onChange={e => setSandboxConfig(c => ({ ...c, cycle: e.target.value }))} disabled={running}>
                  {CYCLE_OPTIONS.map(v => <option key={v} value={v}>Cycle {v}</option>)}
                </select>
              </div>
            )}

            <button
              type="button"
              className="scan-advanced-toggle"
              onClick={() => setShowAdvanced(!showAdvanced)}
            >
              <Settings size={14} />
              <span>Advanced Settings</span>
              {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>

            {showAdvanced && (
              <div className="scan-advanced-content">
                <ModelSelector
                  label="Discovery Model"
                  description="Analyzes the repository and proposes findings. Llama 3.2 is the project default."
                  value={scanMode === 'sandbox' ? sandboxConfig.model : repoConfig.model}
                  models={availableModels}
                  modelsStatus={modelsStatus}
                  disabled={running}
                  onChange={model => scanMode === 'sandbox'
                    ? setSandboxConfig(config => ({ ...config, model }))
                    : setRepoConfig(config => ({ ...config, model }))}
                />

                <ModelSelector
                  label="Challenger Model"
                  description="Reviews and challenges proposed findings. Qwen 2.5 Coder 7B is the project default."
                  value={scanMode === 'sandbox' ? sandboxConfig.challengerModel : repoConfig.challengerModel}
                  models={availableModels}
                  modelsStatus={modelsStatus}
                  disabled={running}
                  onChange={model => scanMode === 'sandbox'
                    ? setSandboxConfig(config => ({ ...config, challengerModel: model }))
                    : setRepoConfig(config => ({ ...config, challengerModel: model }))}
                />

                <div className="scan-field">
                  <label className="scan-label">Workers ({scanMode === 'sandbox' ? sandboxConfig.workers : repoConfig.workers})</label>
                  <input type="range" min={1} max={10}
                    value={scanMode === 'sandbox' ? sandboxConfig.workers : repoConfig.workers}
                    onChange={e => scanMode === 'sandbox'
                      ? setSandboxConfig(c => ({ ...c, workers: +e.target.value }))
                      : setRepoConfig(c => ({ ...c, workers: +e.target.value }))}
                    className="w-full accent-cyan-500" disabled={running}
                  />
                </div>

                <div className="scan-field">
                  <label className="scan-label">Challengers ({scanMode === 'sandbox' ? sandboxConfig.challengers : repoConfig.challengers})</label>
                  <input type="range" min={1} max={2}
                    value={scanMode === 'sandbox' ? sandboxConfig.challengers : repoConfig.challengers}
                    onChange={e => scanMode === 'sandbox'
                      ? setSandboxConfig(c => ({ ...c, challengers: +e.target.value }))
                      : setRepoConfig(c => ({ ...c, challengers: +e.target.value }))}
                    className="w-full accent-orange-500" disabled={running}
                  />
                </div>

                {scanMode === 'repo' && (
                  <div className="scan-field">
                    <label className="scan-label">Max Chunks ({repoConfig.maxChunks === 0 ? 'All' : repoConfig.maxChunks})</label>
                    <input type="range" min={0} max={1000} step={25}
                      value={repoConfig.maxChunks}
                      onChange={e => setRepoConfig(c => ({ ...c, maxChunks: +e.target.value }))}
                      className="w-full accent-violet-500" disabled={running}
                    />
                    <span className="text-xs text-slate-400">0 scans all eligible chunks and may take longer.</span>
                  </div>
                )}

                {scanMode === 'repo' && (
                  <div className="scan-field">
                    <label className="scan-label">SAST Tools</label>
                    <div style={{ display: 'flex', gap: 12 }}>
                      {['bandit', 'semgrep'].map(tool => (
                        <label key={tool} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13, color: '#94a3b8' }}>
                          <input type="checkbox"
                            checked={repoConfig.sastTools.includes(tool)}
                            onChange={() => setRepoConfig(c => ({
                              ...c,
                              sastTools: c.sastTools.includes(tool)
                                ? c.sastTools.filter(t => t !== tool)
                                : [...c.sastTools, tool],
                            }))}
                            className="accent-violet-500" disabled={running || repoConfig.noSast}
                          />
                          {tool}
                        </label>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Live stats */}
          <div className="scan-sidebar__section">
            <h3 className="scan-sidebar__heading">Live Metrics</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {[
                { label: 'Findings', value: liveStats.findings, color: '#a3e635' },
                { label: 'Verdicts', value: liveStats.verdicts, color: '#c084fc' },
                { label: 'Confirmed', value: liveStats.confirmed, color: '#34d399' },
                { label: 'Refuted', value: liveStats.refuted, color: '#f87171' },
              ].map(({ label, value, color }) => (
                <div key={label} style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 8, padding: '8px 10px', textAlign: 'center' }}>
                  <div style={{ color, fontSize: 20, fontWeight: 700 }}>{value}</div>
                  <div style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', marginTop: 2 }}>{label}</div>
                </div>
              ))}
            </div>
          </div>



          {/* Start button */}
          <button
            onClick={scanMode === 'sandbox' ? startSandboxScan : startRepoScan}
            disabled={running || (scanMode === 'repo' && !repoConfig.repo.trim())}
            className="scan-start-btn"
          >
            {running
              ? <><span className="pulse-dot" style={{ color: '#38bdf8' }} /> Scanning…</>
              : <><Play size={14} /> {scanMode === 'sandbox' ? 'Start Sandbox Scan' : 'Start Repository Scan'}</>}
          </button>
        </aside>

        {/* ── Main panel ── */}
        <div className="scan-main">
          {/* Tab bar */}
          <div className="scan-tabs">
            {[
              { id: 'graph', label: '⬡ Agent Graph', icon: <Share2 size={13} /> },
              { id: 'logs', label: `◈ Live Logs${logs.length > 0 ? ` (${logs.length})` : ''}`, icon: <TerminalSquare size={13} /> },
              { id: 'triage', label: `⚖ Triage Queue${triageFindings.length > 0 ? ` (${triageFindings.length})` : ''}`, icon: null },
            ].map(t => (
              <button
                key={t.id}
                className={`scan-tab ${activeTab === t.id ? 'scan-tab--active' : ''}`}
                onClick={() => setActiveTab(t.id as typeof activeTab)}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Agent Graph */}
          {activeTab === 'graph' && (
            <div style={{ flex: 1, position: 'relative' }}>
              {!running && logs.length === 0 && (
                <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10, pointerEvents: 'none' }}>
                  <div className="glass" style={{ padding: '28px 36px', textAlign: 'center', maxWidth: 340 }}>
                    <p style={{ fontSize: 36, marginBottom: 8 }}>⬡</p>
                    <p style={{ color: '#e2e8f0', fontWeight: 600, marginBottom: 4 }}>Swarm Ready</p>
                    <p style={{ color: '#64748b', fontSize: 13, lineHeight: 1.5 }}>Configure your scan in the sidebar and click <strong style={{ color: '#38bdf8' }}>Start</strong> to begin.</p>
                  </div>
                </div>
              )}
              <ReactFlow
                nodes={nodes} edges={edges}
                onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect}
                fitView fitViewOptions={{ padding: 0.25 }}
                proOptions={{ hideAttribution: true }}
              >
                <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#1e293b" />
                <Controls style={{ background: 'rgba(13,23,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8 }} />
                <MiniMap style={{ background: 'rgba(13,23,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8 }} nodeColor="#334155" maskColor="rgba(6,11,20,0.7)" />
              </ReactFlow>
            </div>
          )}

          {/* Logs */}
          {activeTab === 'logs' && (
            <div id="log-feed" style={{ flex: 1, overflowY: 'auto', padding: '12px 16px', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, background: '#030710', lineHeight: 1.7 }}>
              {logs.length === 0 && <div style={{ color: '#1e293b', fontStyle: 'italic', textAlign: 'center', marginTop: 60 }}>{running ? 'Waiting for first log…' : 'Start a scan to see live output.'}</div>}
              {logs.map(entry => (
                <div key={entry.id} className={`log-${entry.type}`} style={{ display: 'flex', gap: 8, marginBottom: 2 }}>
                  <span style={{ opacity: 0.5, userSelect: 'none', flexShrink: 0 }}>{LOG_TYPE_ICON[entry.type]}</span>
                  <span style={{ color: '#334155', flexShrink: 0 }}>[{new Date(entry.ts).toLocaleTimeString()}]</span>
                  <span style={{ color: '#475569', flexShrink: 0 }}>[{entry.agent}]</span>
                  <span style={{ wordBreak: 'break-all' }}>{entry.content}</span>
                </div>
              ))}
              <div ref={logEndRef} />
            </div>
          )}

          {/* Triage Queue */}
          {activeTab === 'triage' && (
            <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
              {triageFindings.length === 0 ? (
                <div style={{ textAlign: 'center', marginTop: 60, color: '#334155', fontStyle: 'italic', fontSize: 13 }}>
                  {running ? 'Triage results appear here as SAST alerts are reviewed…' : 'No triage results yet.'}
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                    <span style={{ color: '#34d399', background: 'rgba(52,211,153,0.1)', border: '1px solid rgba(52,211,153,0.2)', borderRadius: 20, padding: '2px 10px', fontSize: 12 }}>✓ {triageFindings.filter(f => f.triage === 'TP').length} TP</span>
                    <span style={{ color: '#f87171', background: 'rgba(248,113,113,0.1)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 20, padding: '2px 10px', fontSize: 12 }}>✗ {triageFindings.filter(f => f.triage === 'FP').length} FP</span>
                    <span style={{ color: '#94a3b8', background: 'rgba(148,163,184,0.1)', border: '1px solid rgba(148,163,184,0.15)', borderRadius: 20, padding: '2px 10px', fontSize: 12 }}>⋯ {triageFindings.filter(f => f.triage === 'INCONCLUSIVE').length} Inconclusive</span>
                  </div>
                  {triageFindings.map((f, i) => (
                    <div key={i} className="glass" style={{ padding: 14, borderColor: f.triage === 'TP' ? 'rgba(52,211,153,0.3)' : f.triage === 'FP' ? 'rgba(248,113,113,0.2)' : undefined }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 8 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ color: SEV_COLORS[f.severity] || '#94a3b8', background: `${SEV_COLORS[f.severity] || '#94a3b8'}18`, border: `1px solid ${SEV_COLORS[f.severity] || '#94a3b8'}44`, borderRadius: 4, padding: '1px 7px', fontSize: 11, fontWeight: 700 }}>{f.severity}</span>
                          <span style={{ color: '#64748b', fontSize: 12, fontFamily: 'JetBrains Mono, monospace' }}>{f.file}:{f.line}</span>
                        </div>
                        <span style={{
                          fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                          color: f.triage === 'TP' ? '#34d399' : f.triage === 'FP' ? '#f87171' : '#fbbf24',
                          background: f.triage === 'TP' ? 'rgba(52,211,153,0.1)' : f.triage === 'FP' ? 'rgba(248,113,113,0.1)' : 'rgba(251,191,36,0.1)',
                        }}>
                          {f.triage === 'TP' ? '✓ TRUE POSITIVE' : f.triage === 'FP' ? '✗ FALSE POSITIVE' : '⋯ ' + f.triage}
                        </span>
                      </div>
                      <p style={{ color: '#94a3b8', fontSize: 13, margin: 0 }}>{f.message}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
