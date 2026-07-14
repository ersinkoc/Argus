import { useEffect, useState } from 'react'
import { Activity, Users, Database, Shield, AlertTriangle, Eye } from 'lucide-react'
import { api, type HealthResponse, type DashboardResponse, type Session, type Approval } from '@/lib/api'
import { formatDuration } from '@/lib/utils'

interface StatCardProps {
  icon: React.ReactNode
  label: string
  value: string | number
  sublabel?: string
  color?: string
}

function StatCard({ icon, label, value, sublabel, color = 'text-argus-accent' }: StatCardProps) {
  return (
    <div className="card">
      <div className="flex items-center justify-between mb-3">
        <div className={`p-2 rounded-lg bg-argus-bg ${color}`}>{icon}</div>
      </div>
      <div className="text-2xl font-bold text-argus-text">{value}</div>
      <div className="text-sm text-argus-muted mt-1">{label}</div>
      {sublabel && <div className="text-xs text-argus-muted mt-0.5">{sublabel}</div>}
    </div>
  )
}

export function DashboardPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [dashboard, setDashboard] = useState<DashboardResponse | null>(null)
  const [sessions, setSessions] = useState<Session[]>([])
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchData = async () => {
    try {
      const [h, d, s, a] = await Promise.all([
        api.health.get(),
        api.dashboard.get(),
        api.sessions.list().catch(() => []),
        api.approvals.list().catch(() => []),
      ])
      setHealth(h)
      setDashboard(d)
      setSessions(Array.isArray(s) ? s : [])
      setApprovals(Array.isArray(a) ? a : [])
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Activity className="w-8 h-8 text-argus-accent animate-spin" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="card text-center py-12">
        <AlertTriangle className="w-12 h-12 text-argus-danger mx-auto mb-4" />
        <p className="text-argus-danger font-medium">Failed to connect to Argus API</p>
        <p className="text-argus-muted text-sm mt-2">{error}</p>
        <button onClick={fetchData} className="btn-primary mt-4">Retry</button>
      </div>
    )
  }

  const overview = dashboard?.overview || {}
  const traffic = dashboard?.traffic || {}
  const pool = dashboard?.pool || {}

  return (
    <div className="space-y-6">
      {/* Status Bar */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <div className={`w-3 h-3 rounded-full ${health?.status === 'healthy' ? 'bg-argus-success' : 'bg-argus-danger'}`} />
          <span className="text-sm font-medium">
            {health?.status === 'healthy' ? 'Healthy' : 'Degraded'}
          </span>
        </div>
        <span className="text-sm text-argus-muted">
          Uptime: {overview.uptime || '-'}
        </span>
        {health?.version && (
          <span className="text-sm text-argus-muted">v{health.version}</span>
        )}
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={<Users className="w-5 h-5" />}
          label="Active Sessions"
          value={overview.active_sessions ?? 0}
          color="text-blue-400"
        />
        <StatCard
          icon={<Activity className="w-5 h-5" />}
          label="Total Commands"
          value={traffic.total_commands ?? 0}
          sublabel={`${traffic.blocked_commands ?? 0} blocked`}
          color="text-emerald-400"
        />
        <StatCard
          icon={<Shield className="w-5 h-5" />}
          label="Results Masked"
          value={traffic.masked_results ?? 0}
          sublabel={`${traffic.total_rows ?? 0} rows processed`}
          color="text-amber-400"
        />
        <StatCard
          icon={<Database className="w-5 h-5" />}
          label="Pool Connections"
          value={pool.active_connections ?? 0}
          sublabel={`${pool.idle_connections ?? 0} idle / ${pool.total_pools ?? 0} pools`}
          color="text-purple-400"
        />
      </div>

      {/* Targets */}
      {health?.pools && Object.keys(health.pools).length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-argus-text uppercase tracking-wider mb-3">
            Database Targets
          </h2>
          <div className="space-y-2">
            {Object.entries(health.pools).map(([name, p]) => (
              <div key={name} className="card flex items-center justify-between py-3">
                <div className="flex items-center gap-3">
                  <div className={`w-2.5 h-2.5 rounded-full ${p.Healthy ? 'bg-argus-success' : 'bg-argus-danger'}`} />
                  <span className="font-medium text-sm">{name}</span>
                </div>
                <div className="flex items-center gap-4 text-xs text-argus-muted">
                  <span>{p.Target}</span>
                  <span>A:{p.Active} I:{p.Idle}/{p.Max}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active Sessions */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-argus-text uppercase tracking-wider">
            Active Sessions ({sessions.length})
          </h2>
        </div>
        {sessions.length === 0 ? (
          <div className="card text-center py-8 text-argus-muted text-sm">
            No active sessions
          </div>
        ) : (
          <div className="card overflow-x-auto p-0">
            <table className="w-full">
              <thead>
                <tr className="border-b border-argus-border">
                  <th className="table-header">ID</th>
                  <th className="table-header">User</th>
                  <th className="table-header">Database</th>
                  <th className="table-header">Duration</th>
                  <th className="table-header">Commands</th>
                </tr>
              </thead>
              <tbody>
                {sessions.slice(0, 10).map((s) => (
                  <tr key={s.id} className="hover:bg-argus-bg/50">
                    <td className="table-cell font-mono text-xs">{s.id.substring(0, 8)}</td>
                    <td className="table-cell">{s.username}</td>
                    <td className="table-cell text-argus-muted">{s.database || '-'}</td>
                    <td className="table-cell">{formatDuration(s.duration)}</td>
                    <td className="table-cell">{s.command_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pending Approvals */}
      {approvals.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-argus-text uppercase tracking-wider">
              Pending Approvals ({approvals.length})
            </h2>
          </div>
          <div className="space-y-2">
            {approvals.map((a) => (
              <div key={a.id} className="card flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-medium text-amber-400 text-sm">{a.username}</span>
                    <span className="text-argus-muted text-xs">@{a.database}</span>
                    {a.risk_level && (
                      <span className={`badge ${
                        a.risk_level === 'critical' ? 'badge-err' :
                        a.risk_level === 'high' ? 'badge-warn' : 'badge-info'
                      }`}>{a.risk_level}</span>
                    )}
                  </div>
                  <div className="text-xs text-argus-muted truncate">{a.sql}</div>
                </div>
                <div className="flex gap-2 ml-4 shrink-0">
                  <button className="btn-success btn-sm">Approve</button>
                  <button className="btn-danger btn-sm">Deny</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
