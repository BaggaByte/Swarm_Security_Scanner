// ─── Shared product-wide types ───────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'new' | 'confirmed' | 'fixed' | 'accepted_risk' | 'false_positive';
export type LogType = 'PHASE' | 'WORKER' | 'CHALLENGER' | 'VERDICT' | 'SYSTEM' | 'ERROR' | 'DONE';
export type AppMode = 'sandbox' | 'repo';
export type ScanStatus = 'running' | 'done' | 'error' | 'queued';

// ── Finding ──────────────────────────────────────────────────────────────────

export interface Finding {
  id: string;
  repository: string;
  file: string;
  line: number;
  title: string;
  description: string;
  severity: Severity;
  cwe: string | null;
  owasp: string | null;
  status: FindingStatus;
  owner?: string;
  aiVerdict: 'TP' | 'FP' | 'INCONCLUSIVE' | 'PENDING';
  swarmRationale: string;
  codeSnippet?: string;
  exploitPath?: string;
  exploitVerified?: boolean;
  exploitOutput?: string;
  remediationSuggestion?: string;
  tool: string;
  ruleId: string;
  firstDetected: number;
  lastDetected: number;
  scanId: string;
}

// ── Scan Run ─────────────────────────────────────────────────────────────────

export interface ScanRun {
  id: string;
  type: 'sandbox' | 'repo';
  repository?: string;
  status: ScanStatus;
  startedAt: number;
  finishedAt?: number;
  model: string;
  challengerModel: string;
  workers: number;
  challengers: number;
  findingCount: number;
  confirmedCount: number;
  fpCount: number;
  metrics?: ScanMetrics;
}

export interface ScanMetrics {
  durationSeconds: number;
  tokensEstimated: number;
  sastFindingCount: number;
  swarmConfirmed: number;
  fpReductionRate: number;
  precisionPct?: number;
  recallPct?: number;
  f1?: number;
  deltaVsSast?: number;
}

// ── Repository ────────────────────────────────────────────────────────────────

export interface Repository {
  id: string;
  name: string;
  url: string;
  type: 'github' | 'gitlab' | 'local';
  lastScanned?: number;
  openFindings: number;
  criticalCount: number;
  highCount: number;
}

// ── Log Entry (live stream) ───────────────────────────────────────────────────

export interface LogEntry {
  id: number;
  type: LogType;
  agent: string;
  content: string;
  ts: number;
  finding?: any;
  verdict?: string;
  rationale?: string;
  metrics?: any;
}

// ── Triage Finding (parsed from SSE) ─────────────────────────────────────────

export interface TriageFinding {
  tool: string;
  ruleId: string;
  ruleName: string;
  file: string;
  line: number;
  severity: string;
  confidence: string;
  cwe: string | null;
  message: string;
  code: string;
  triage?: 'TP' | 'FP' | 'INCONCLUSIVE' | 'PENDING';
  triageRationale?: string;
}

// ── Dashboard stats ───────────────────────────────────────────────────────────

export interface DashboardStats {
  totalFindings: number;
  criticalOpen: number;
  highOpen: number;
  fixedThisWeek: number;
  avgTimeToFix: number;
  fpRate: number;
  totalScans: number;
  repositoriesMonitored: number;
}

// ── Scan config (forms) ───────────────────────────────────────────────────────

export interface SandboxScanConfig {
  model: string;
  challengerModel: string;
  cycle: string;
  workers: number;
  challengers: number;
}

export interface RepoScanConfig {
  repo: string;
  model: string;
  challengerModel: string;
  workers: number;
  challengers: number;
  sastTools: string[];
  noSast: boolean;
  maxChunks: number;
}
