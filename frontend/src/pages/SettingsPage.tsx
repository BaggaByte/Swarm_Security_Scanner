/**
 * Settings & Organization Management Page
 * ========================================
 * Sprint 3.1: Complete management console for:
 *   • Webhook Integrations (Slack, Discord, MS Teams, Custom Webhook)
 *   • Team Members & RBAC Roles (Admin, Analyst, Viewer)
 *   • Compliance & Security Audit Trail
 *   • API Key Configuration & Testing
 */

import React, { useState, useEffect } from 'react';
import {
  Settings, Bell, Users, Shield, Key, Send, Trash2,
  Plus, CheckCircle, AlertTriangle, RefreshCw, Lock, ExternalLink
} from 'lucide-react';
import { useStore } from '../useStore';

interface NotificationSetting {
  id: string;
  webhook_url: string;
  channel_type: string;
  enabled: boolean;
  notify_on_critical: boolean;
  notify_on_complete: boolean;
}

interface UserRecord {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'analyst' | 'viewer';
  created_at: number;
}

interface AuditLogRecord {
  id: number;
  user_email: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  details?: string;
  timestamp: number;
}

export default function SettingsPage() {
  const { apiKey, setApiKey } = useStore();
  const [activeTab, setActiveTab] = useState<'notifications' | 'team' | 'audit' | 'api'>('notifications');

  // Notification state
  const [notifications, setNotifications] = useState<NotificationSetting[]>([]);
  const [newWebhookUrl, setNewWebhookUrl] = useState('');
  const [newChannelType, setNewChannelType] = useState('slack');
  const [testStatus, setTestStatus] = useState<Record<string, 'idle' | 'testing' | 'success' | 'error'>>({});

  // Team state
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [newUserName, setNewUserName] = useState('');
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserRole, setNewUserRole] = useState<'admin' | 'analyst' | 'viewer'>('analyst');
  const [isAddingUser, setIsAddingUser] = useState(false);

  // Audit state
  const [auditLogs, setAuditLogs] = useState<AuditLogRecord[]>([]);
  const [isLoadingAudit, setIsLoadingAudit] = useState(false);

  // API Key state
  const [tempApiKey, setTempApiKey] = useState(apiKey || '');
  const [keySaved, setKeySaved] = useState(false);

  const getHeaders = () => ({
    'Content-Type': 'application/json',
    ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
  });

  const apiBase = window.location.origin.includes('5173') ? 'http://127.0.0.1:8001' : '';

  // Load notification settings
  const loadNotifications = async () => {
    try {
      const res = await fetch(`${apiBase}/api/settings/notifications`, { credentials: 'omit', headers: getHeaders() });
      if (res.ok) {
        const data = await res.json();
        setNotifications(data);
      }
    } catch {
      // Fallback
    }
  };

  // Load users
  const loadUsers = async () => {
    try {
      const res = await fetch(`${apiBase}/api/users`, { credentials: 'omit', headers: getHeaders() });
      if (res.ok) {
        const data = await res.json();
        setUsers(data);
      }
    } catch {
      // Fallback
    }
  };

  // Load audit logs
  const loadAuditLogs = async () => {
    setIsLoadingAudit(true);
    try {
      const res = await fetch(`${apiBase}/api/audit-logs?limit=50`, { credentials: 'omit', headers: getHeaders() });
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data);
      }
    } catch {
      // Fallback
    } finally {
      setIsLoadingAudit(false);
    }
  };

  useEffect(() => {
    loadNotifications();
    loadUsers();
    loadAuditLogs();
  }, [apiKey]);

  // Save webhook
  const handleSaveWebhook = async () => {
    if (!newWebhookUrl.trim()) return;
    try {
      const res = await fetch(`${apiBase}/api/settings/notifications`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          webhook_url: newWebhookUrl.trim(),
          channel_type: newChannelType,
          enabled: true,
          notify_on_critical: true,
          notify_on_complete: true,
        }),
      });
      if (res.ok) {
        setNewWebhookUrl('');
        loadNotifications();
        loadAuditLogs();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Test webhook
  const handleTestWebhook = async (setting: NotificationSetting) => {
    setTestStatus(prev => ({ ...prev, [setting.id]: 'testing' }));
    try {
      const res = await fetch(`${apiBase}/api/settings/notifications/test`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          webhook_url: setting.webhook_url,
          channel_type: setting.channel_type,
        }),
      });
      if (res.ok) {
        setTestStatus(prev => ({ ...prev, [setting.id]: 'success' }));
        setTimeout(() => setTestStatus(prev => ({ ...prev, [setting.id]: 'idle' })), 3000);
      } else {
        setTestStatus(prev => ({ ...prev, [setting.id]: 'error' }));
      }
    } catch {
      setTestStatus(prev => ({ ...prev, [setting.id]: 'error' }));
    }
  };

  // Add user
  const handleAddUser = async () => {
    if (!newUserEmail.trim() || !newUserName.trim()) return;
    setIsAddingUser(true);
    try {
      const res = await fetch(`${apiBase}/api/users`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          name: newUserName.trim(),
          email: newUserEmail.trim(),
          role: newUserRole,
        }),
      });
      if (res.ok) {
        setNewUserName('');
        setNewUserEmail('');
        loadUsers();
        loadAuditLogs();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsAddingUser(false);
    }
  };

  // Remove user
  const handleRemoveUser = async (userId: string) => {
    try {
      const res = await fetch(`${apiBase}/api/users/${userId}`, {
        method: 'DELETE',
        headers: getHeaders(),
      });
      if (res.ok) {
        loadUsers();
        loadAuditLogs();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Save API Key
  const handleSaveApiKey = () => {
    setApiKey(tempApiKey.trim());
    setKeySaved(true);
    setTimeout(() => setKeySaved(false), 3000);
  };

  return (
    <div className="page-container" style={{ maxWidth: 1200, margin: '0 auto' }}>
      <div className="page-header" style={{ marginBottom: 24 }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Settings size={24} style={{ color: 'var(--color-accent, #38bdf8)' }} />
            Organization & Security Settings
          </h1>
          <p className="page-subtitle">Configure notification webhooks, manage team access & roles, and inspect security audit trails.</p>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 8, borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: 12, marginBottom: 24 }}>
        <button
          onClick={() => setActiveTab('notifications')}
          className={`filter-toggle ${activeTab === 'notifications' ? 'filter-toggle--active' : ''}`}
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Bell size={14} /> Webhooks & Alerts ({notifications.length})
        </button>
        <button
          onClick={() => setActiveTab('team')}
          className={`filter-toggle ${activeTab === 'team' ? 'filter-toggle--active' : ''}`}
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Users size={14} /> Team & RBAC ({users.length})
        </button>
        <button
          onClick={() => setActiveTab('audit')}
          className={`filter-toggle ${activeTab === 'audit' ? 'filter-toggle--active' : ''}`}
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Shield size={14} /> Audit Trail ({auditLogs.length})
        </button>
        <button
          onClick={() => setActiveTab('api')}
          className={`filter-toggle ${activeTab === 'api' ? 'filter-toggle--active' : ''}`}
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Key size={14} /> API Authentication
        </button>
      </div>

      {/* TAB 1: WEBHOOKS & ALERTS */}
      {activeTab === 'notifications' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, padding: 20 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Plus size={16} style={{ color: '#38bdf8' }} /> Connect Outgoing Webhook
            </h3>
            <p style={{ color: 'var(--color-text-muted)', fontSize: 13, marginBottom: 16 }}>
              Receive instant alerts in Slack, Discord, Microsoft Teams, or custom webhook endpoints whenever critical vulnerabilities are confirmed.
            </p>

            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <select
                value={newChannelType}
                onChange={e => setNewChannelType(e.target.value)}
                style={{ padding: '8px 12px', background: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, color: '#e2e8f0', fontSize: 13 }}
              >
                <option value="slack">Slack Incoming Webhook</option>
                <option value="discord">Discord Webhook</option>
                <option value="teams">Microsoft Teams Connector</option>
                <option value="generic">Generic JSON Webhook</option>
              </select>

              <input
                value={newWebhookUrl}
                onChange={e => setNewWebhookUrl(e.target.value)}
                placeholder="https://hooks.slack.com/services/... or https://discord.com/api/webhooks/..."
                style={{ flex: 1, minWidth: 280, padding: '8px 12px', background: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, color: '#e2e8f0', fontSize: 13 }}
              />

              <button
                onClick={handleSaveWebhook}
                disabled={!newWebhookUrl.trim()}
                style={{ padding: '8px 16px', background: '#38bdf8', color: '#0f172a', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 13, cursor: 'pointer' }}
              >
                Add Webhook
              </button>
            </div>
          </div>

          <div style={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, padding: 20 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 14 }}>Active Notification Channels ({notifications.length})</h3>
            {notifications.length === 0 ? (
              <p style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>No webhook channels configured yet. Add one above to enable alerts.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {notifications.map(n => (
                  <div key={n.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#0f172a', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '12px 16px' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ textTransform: 'uppercase', fontSize: 11, fontWeight: 700, color: '#38bdf8', background: '#38bdf818', padding: '2px 8px', borderRadius: 4 }}>
                          {n.channel_type}
                        </span>
                        <span style={{ fontFamily: 'monospace', fontSize: 13, color: '#e2e8f0' }}>
                          {n.webhook_url.replace(/(https?:\/\/[^/]+\/[^/]+\/).*/, '$1••••••••')}
                        </span>
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>
                        Alerts: {n.notify_on_critical ? 'Critical TPs' : ''} {n.notify_on_complete ? '& Full Scan Summary' : ''}
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <button
                        onClick={() => handleTestWebhook(n)}
                        disabled={testStatus[n.id] === 'testing'}
                        style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: '#34d39918', border: '1px solid #34d39944', color: '#34d399', borderRadius: 6, fontSize: 12, cursor: 'pointer' }}
                      >
                        <Send size={12} />
                        {testStatus[n.id] === 'testing' ? 'Testing…' : (testStatus[n.id] === 'success' ? '✓ Ping Sent!' : (testStatus[n.id] === 'error' ? '✗ Failed' : 'Test Ping'))}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: TEAM & RBAC */}
      {activeTab === 'team' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, padding: 20 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Plus size={16} style={{ color: '#38bdf8' }} /> Invite Team Member
            </h3>

            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <input
                value={newUserName}
                onChange={e => setNewUserName(e.target.value)}
                placeholder="Full Name"
                style={{ minWidth: 180, padding: '8px 12px', background: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, color: '#e2e8f0', fontSize: 13 }}
              />
              <input
                value={newUserEmail}
                onChange={e => setNewUserEmail(e.target.value)}
                placeholder="developer@company.com"
                style={{ flex: 1, minWidth: 240, padding: '8px 12px', background: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, color: '#e2e8f0', fontSize: 13 }}
              />
              <select
                value={newUserRole}
                onChange={e => setNewUserRole(e.target.value as any)}
                style={{ padding: '8px 12px', background: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, color: '#e2e8f0', fontSize: 13 }}
              >
                <option value="admin">Admin (Full Access)</option>
                <option value="analyst">Security Analyst (Scan & Triage)</option>
                <option value="viewer">Viewer (Read-Only)</option>
              </select>
              <button
                onClick={handleAddUser}
                disabled={isAddingUser || !newUserName.trim() || !newUserEmail.trim()}
                style={{ padding: '8px 16px', background: '#38bdf8', color: '#0f172a', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 13, cursor: 'pointer' }}
              >
                {isAddingUser ? 'Adding…' : 'Add Member'}
              </button>
            </div>
          </div>

          <div style={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, padding: 20 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 14 }}>Active Members ({users.length})</h3>
            {users.length === 0 ? (
              <p style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>No team members added yet.</p>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', color: 'var(--color-text-muted)', textAlign: 'left' }}>
                    <th style={{ padding: '8px 12px' }}>Name</th>
                    <th style={{ padding: '8px 12px' }}>Email</th>
                    <th style={{ padding: '8px 12px' }}>Role</th>
                    <th style={{ padding: '8px 12px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(u => (
                    <tr key={u.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <td style={{ padding: '12px', fontWeight: 600, color: '#f8fafc' }}>{u.name}</td>
                      <td style={{ padding: '12px', color: '#94a3b8' }}>{u.email}</td>
                      <td style={{ padding: '12px' }}>
                        <span style={{
                          padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
                          background: u.role === 'admin' ? '#ef444418' : (u.role === 'analyst' ? '#38bdf818' : '#94a3b818'),
                          color: u.role === 'admin' ? '#ef4444' : (u.role === 'analyst' ? '#38bdf8' : '#94a3b8'),
                          border: `1px solid ${u.role === 'admin' ? '#ef444444' : (u.role === 'analyst' ? '#38bdf844' : '#94a3b844')}`
                        }}>
                          {u.role}
                        </span>
                      </td>
                      <td style={{ padding: '12px', textAlign: 'right' }}>
                        <button
                          onClick={() => handleRemoveUser(u.id)}
                          style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', padding: 4 }}
                          title="Remove user"
                        >
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: AUDIT TRAIL */}
      {activeTab === 'audit' && (
        <div style={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700 }}>SOC2 & Security Compliance Audit Trail</h3>
            <button
              onClick={loadAuditLogs}
              disabled={isLoadingAudit}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px', background: 'none', border: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', borderRadius: 6, fontSize: 12, cursor: 'pointer' }}
            >
              <RefreshCw size={12} className={isLoadingAudit ? 'animate-spin' : ''} /> Refresh
            </button>
          </div>

          {auditLogs.length === 0 ? (
            <p style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>No audit logs recorded yet.</p>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', color: 'var(--color-text-muted)', textAlign: 'left' }}>
                  <th style={{ padding: '8px 12px' }}>Timestamp</th>
                  <th style={{ padding: '8px 12px' }}>Actor</th>
                  <th style={{ padding: '8px 12px' }}>Action</th>
                  <th style={{ padding: '8px 12px' }}>Resource</th>
                  <th style={{ padding: '8px 12px' }}>Details</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map(log => (
                  <tr key={log.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <td style={{ padding: '10px 12px', color: '#64748b', fontFamily: 'monospace', fontSize: 11 }}>
                      {new Date(log.timestamp * 1000).toLocaleString()}
                    </td>
                    <td style={{ padding: '10px 12px', color: '#e2e8f0', fontWeight: 600 }}>{log.user_email}</td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{log.action}</span>
                    </td>
                    <td style={{ padding: '10px 12px', color: '#94a3b8' }}>{log.resource_type}</td>
                    <td style={{ padding: '10px 12px', color: '#94a3b8', fontSize: 12 }}>{log.details || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* TAB 4: API AUTH */}
      {activeTab === 'api' && (
        <div style={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, padding: 20 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Key size={16} style={{ color: '#38bdf8' }} /> Swarm API Key
          </h3>
          <p style={{ color: 'var(--color-text-muted)', fontSize: 13, marginBottom: 16 }}>
            Set the master API Key used by this browser session to authenticate with protected Swarm endpoints and CI/CD pipelines.
          </p>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center', maxWidth: 600 }}>
            <input
              type="password"
              value={tempApiKey}
              onChange={e => setTempApiKey(e.target.value)}
              placeholder="Enter master API Key (e.g. from .env SWARM_API_KEY)..."
              style={{ flex: 1, padding: '8px 12px', background: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, color: '#e2e8f0', fontSize: 13 }}
            />
            <button
              onClick={handleSaveApiKey}
              style={{ padding: '8px 16px', background: '#38bdf8', color: '#0f172a', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 13, cursor: 'pointer' }}
            >
              {keySaved ? 'Saved!' : 'Save Key'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
