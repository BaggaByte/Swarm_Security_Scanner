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

const mockNodes = [
  { id: 'client', position: { x: 50, y: 150 }, data: { label: 'Public Internet', type: 'external', icon: <Globe size={14} /> } },
  { id: 'api-gateway', position: { x: 300, y: 150 }, data: { label: 'API Gateway', type: 'entrypoint', tags: ['Internet-Facing'], icon: <Network size={14} /> } },
  { id: 'auth-service', position: { x: 550, y: 50 }, data: { label: 'Auth Service', type: 'internal', icon: <Lock size={14} /> } },
  { id: 'user-service', position: { x: 550, y: 250 }, data: { label: 'User Service', type: 'internal', tags: ['PII'], icon: <Network size={14} /> }, style: { border: '2px solid #f87171', boxShadow: '0 0 15px rgba(248,113,113,0.3)' } },
  { id: 'db-users', position: { x: 800, y: 250 }, data: { label: 'Users DB', type: 'database', tags: ['PII', 'High-Risk'], icon: <Database size={14} /> } },
];

const mockEdges = [
  { id: 'e1', source: 'client', target: 'api-gateway', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#475569' } },
  { id: 'e2', source: 'api-gateway', target: 'auth-service', markerEnd: { type: MarkerType.ArrowClosed, color: '#475569' } },
  { id: 'e3', source: 'api-gateway', target: 'user-service', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#f87171' }, style: { stroke: '#f87171', strokeWidth: 2 } },
  { id: 'e4', source: 'user-service', target: 'db-users', markerEnd: { type: MarkerType.ArrowClosed, color: '#f87171' }, style: { stroke: '#f87171', strokeWidth: 2 } },
];

function CustomNode({ data }: { data: any }) {
  return (
    <div style={{
      background: 'rgba(13,23,38,0.95)', border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: 8, padding: '10px 14px', color: '#e2e8f0',
      minWidth: 140, boxShadow: '0 4px 6px -1px rgba(0,0,0,0.5)',
      fontFamily: 'Inter, sans-serif'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <span style={{ color: '#38bdf8' }}>{data.icon}</span>
        <strong style={{ fontSize: 13, letterSpacing: '0.02em' }}>{data.label}</strong>
      </div>
      
      {data.tags && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 8 }}>
          {data.tags.map((t: string) => (
            <span key={t} style={{
              background: t === 'PII' || t === 'High-Risk' ? 'rgba(248,113,113,0.15)' : 'rgba(56,189,248,0.1)',
              color: t === 'PII' || t === 'High-Risk' ? '#fca5a5' : '#7dd3fc',
              padding: '2px 6px', borderRadius: 4, fontSize: 9, fontWeight: 700, textTransform: 'uppercase'
            }}>{t}</span>
          ))}
        </div>
      )}
      
      {data.id === 'user-service' && (
        <div style={{ position: 'absolute', top: -8, right: -8, background: '#f87171', color: 'white', borderRadius: '50%', width: 20, height: 20, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <ShieldAlert size={12} />
        </div>
      )}
    </div>
  );
}

const nodeTypes = { custom: CustomNode };

export default function ArchitecturePage() {
  const nodes = useMemo(() => mockNodes.map(n => ({ ...n, type: 'custom' })), []);
  
  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="page-header" style={{ flexShrink: 0 }}>
        <div>
          <h1 className="page-title">Attack Surface</h1>
          <p className="page-subtitle">Security Knowledge Graph mapped across 1 repository</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn-primary" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#e2e8f0', boxShadow: 'none' }}>
            Regenerate Graph
          </button>
        </div>
      </div>
      
      <div style={{ flex: 1, border: '1px solid var(--color-border)', borderRadius: 12, overflow: 'hidden', position: 'relative' }}>
        <ReactFlow nodes={nodes} edges={mockEdges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.2 }}>
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#1e293b" />
          <Controls style={{ background: 'rgba(13,23,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8 }} />
          <MiniMap style={{ background: 'rgba(13,23,38,0.8)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8 }} nodeColor="#334155" maskColor="rgba(6,11,20,0.7)" />
        </ReactFlow>
        
        <div style={{ position: 'absolute', top: 16, right: 16, width: 280, background: 'rgba(13,23,38,0.85)', backdropFilter: 'blur(4px)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 12, padding: 16 }}>
          <h3 style={{ margin: '0 0 12px 0', fontSize: 13, color: 'white', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Risk Context</h3>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                <span style={{ color: '#94a3b8' }}>Business Impact Score</span>
                <span style={{ color: '#fca5a5', fontWeight: 600 }}>9.2 / 10</span>
              </div>
              <div style={{ height: 4, background: 'rgba(255,255,255,0.1)', borderRadius: 2 }}>
                <div style={{ height: '100%', width: '92%', background: '#f87171', borderRadius: 2 }} />
              </div>
            </div>
            
            <p style={{ color: '#94a3b8', fontSize: 12, lineHeight: 1.5, margin: 0 }}>
              <strong style={{ color: '#e2e8f0' }}>Vulnerability detected</strong> in <code style={{ color: '#38bdf8' }}>user-service</code>. 
              Because this component is tagged with <span style={{ color: '#fca5a5' }}>PII</span> and is reachable from <span style={{ color: '#7dd3fc' }}>Internet-Facing</span> nodes, the CVSS has been automatically escalated to Critical.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
