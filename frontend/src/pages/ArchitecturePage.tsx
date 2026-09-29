/**
 * Architecture & Attack Surface — visual graph of the repository's components.
 */

import React, { useMemo, useState } from 'react';
import {
  ReactFlow, Background, Controls, MiniMap,
  BackgroundVariant, MarkerType
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Network, Database, Globe, Lock, ShieldAlert } from 'lucide-react';

import { useStore } from '../useStore';

function renderNodeIcon(icon: any) {
  if (React.isValidElement(icon)) return icon;
  switch (icon) {
    case 'Globe': return <Globe size={14} />;
    case 'Network': return <Network size={14} />;
    case 'Database': return <Database size={14} />;
    case 'Lock': return <Lock size={14} />;
    case 'ShieldAlert': return <ShieldAlert size={14} />;
    default: return <Network size={14} />;
  }
}

function CustomNode({ data }: { data: any }) {
  const isHighRisk = data.isHighRisk || data.tags?.some((t: string) => 
    t.toLowerCase().includes('risk') || t.toLowerCase().includes('rce') || t.toLowerCase().includes('surface')
  );

  return (
    <div style={{
      background: 'rgba(13,23,38,0.95)',
      border: isHighRisk ? '1px solid rgba(248,113,113,0.5)' : '1px solid rgba(255,255,255,0.1)',
      borderRadius: 8, padding: '10px 14px', color: '#e2e8f0',
      minWidth: 150,
      boxShadow: isHighRisk ? '0 0 12px rgba(248,113,113,0.2)' : '0 4px 6px -1px rgba(0,0,0,0.5)',
      fontFamily: 'Inter, sans-serif',
      position: 'relative'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <span style={{ color: isHighRisk ? '#f87171' : '#38bdf8' }}>{renderNodeIcon(data.icon)}</span>
        <strong style={{ fontSize: 13, letterSpacing: '0.02em' }}>{data.label}</strong>
      </div>
      
      {data.tags && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 8 }}>
          {data.tags.map((t: string) => {
            const isDangerTag = t.toLowerCase().includes('risk') || t.toLowerCase().includes('rce') || t.toLowerCase().includes('untrusted');
            return (
              <span key={t} style={{
                background: isDangerTag ? 'rgba(248,113,113,0.15)' : 'rgba(56,189,248,0.1)',
                color: isDangerTag ? '#fca5a5' : '#7dd3fc',
                padding: '2px 6px', borderRadius: 4, fontSize: 9, fontWeight: 700, textTransform: 'uppercase'
              }}>{t}</span>
            );
          })}
        </div>
      )}
      
      {data.isHighRisk && (
        <div style={{ position: 'absolute', top: -8, right: -8, background: '#f87171', color: 'white', borderRadius: '50%', width: 20, height: 20, display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 8px rgba(248,113,113,0.6)' }}>
          <ShieldAlert size={12} />
        </div>
      )}
    </div>
  );
}

const nodeTypes = { custom: CustomNode };


export default function ArchitecturePage() {
  const { apiKey, repositories } = useStore();
  const [selectedRepo, setSelectedRepo] = useState<string>(repositories[0]?.url || '');
  const [graphData, setGraphData] = useState<{ nodes: any[], edges: any[], raw?: any } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchGraph = React.useCallback(() => {
    if (!selectedRepo || !apiKey) return;
    setLoading(true);
    setError(null);
    const API = window.location.origin.includes('localhost:5173') ? 'http://localhost:8001' : '';
    fetch(`${API}/api/architecture?repo=${encodeURIComponent(selectedRepo)}`, {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    })
      .then(res => {
        if (!res.ok) throw new Error('Architecture map not found for this repository. Run a scan first.');
        return res.json();
      })
      .then(data => {
        setGraphData({
          nodes: data.nodes.map((n: any) => ({ ...n, type: 'custom' })),
          edges: data.edges,
          raw: data.raw
        });
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [selectedRepo, apiKey]);

  React.useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  const nodes = useMemo(() => graphData?.nodes || [], [graphData]);
  const edges = useMemo(() => graphData?.edges || [], [graphData]);
  
  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="page-header" style={{ flexShrink: 0 }}>
        <div>
          <h1 className="page-title">Attack Surface</h1>
          <p className="page-subtitle">Security Knowledge Graph mapped across {repositories.length} repositories</p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select 
            value={selectedRepo}
            onChange={e => setSelectedRepo(e.target.value)}
            style={{ padding: '6px 12px', borderRadius: 6, background: '#0f172a', border: '1px solid #334155', color: '#e2e8f0' }}
          >
            {repositories.map(r => (
              <option key={r.id} value={r.url}>{r.name}</option>
            ))}
          </select>
          <button onClick={fetchGraph} className="btn-primary" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#e2e8f0', boxShadow: 'none' }}>
            Regenerate Graph
          </button>
        </div>
      </div>
      
      <div style={{ flex: 1, border: '1px solid var(--color-border)', borderRadius: 12, overflow: 'hidden', position: 'relative' }}>
        {loading && <div style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#38bdf8' }}>Loading map...</div>}
        {error && <div style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.8)', zIndex: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#f87171' }}>{error}</div>}
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.2 }}>
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#1e293b" />
          <Controls style={{ background: 'rgba(13,23,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8 }} />
          <MiniMap style={{ background: 'rgba(13,23,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8 }} nodeColor="#334155" maskColor="rgba(6,11,20,0.7)" />
        </ReactFlow>
        
        <div style={{ position: 'absolute', top: 16, right: 16, width: 290, background: 'rgba(13,23,38,0.85)', backdropFilter: 'blur(8px)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 12, padding: 16 }}>
          <h3 style={{ margin: '0 0 12px 0', fontSize: 13, color: 'white', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Attack Surface Analysis</h3>
          
          {graphData?.raw ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                <span style={{ color: '#94a3b8' }}>Repository Target</span>
                <span style={{ color: '#7dd3fc', fontWeight: 600 }}>{graphData.raw.repo_name}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                <span style={{ color: '#94a3b8' }}>Components / Flow Paths</span>
                <span style={{ color: '#38bdf8', fontWeight: 600 }}>{nodes.length} nodes / {edges.length} flows</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                <span style={{ color: '#94a3b8' }}>Ingress Endpoints</span>
                <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{graphData.raw.entry_points?.length || 1} identified</span>
              </div>
              
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 10 }}>
                <div style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase', fontWeight: 700, marginBottom: 6 }}>Security Surface Elements</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {graphData.raw.technology_inventory?.map((tech: string) => {
                    const isDangerous = ['subprocess', 'deserialization', 'sql'].includes(tech);
                    return (
                      <span key={tech} style={{
                        background: isDangerous ? 'rgba(248,113,113,0.15)' : 'rgba(56,189,248,0.1)',
                        color: isDangerous ? '#fca5a5' : '#7dd3fc',
                        padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 600
                      }}>
                        {tech.toUpperCase()}
                      </span>
                    );
                  })}
                </div>
              </div>

              <p style={{ color: '#94a3b8', fontSize: 11, lineHeight: 1.4, margin: 0 }}>
                {graphData.raw.total_files} files analyzed ({graphData.raw.total_lines?.toLocaleString() || 0} LOC). Ingress flows through public boundary into routing entry points and downstream persistent sinks.
              </p>
            </div>
          ) : (
            <p style={{ color: '#94a3b8', fontSize: 12, lineHeight: 1.5, margin: 0 }}>
              No architecture scan available for this repository. Run a scan to map the attack surface.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
