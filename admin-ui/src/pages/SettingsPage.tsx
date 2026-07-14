import { useEffect, useState } from 'react'
import { Settings, RefreshCw, Download, ShieldCheck, Server, HardDrive, Activity, Key, LogOut } from 'lucide-react'
import { api, type ConfigExport, type StatsResponse, type PoolHealth, type PluginInfo } from '@/lib/api'
import { getToken, setToken as saveToken, clearToken } from '@/components/TokenGate'

export function SettingsPage() {
  const [config, setConfig] = useState<ConfigExport | null>(null)
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [poolHealth, setPoolHealth] = useState<PoolHealth[]>([])
  const [plugins, setPlugins] = useState<PluginInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [tokenInput, setTokenInput] = useState('')
  const [tokenMsg, setTokenMsg] = useState<string | null>(null)
  const [tokenErr, setTokenErr] = useState<string | null>(null)
  const [compactResult, setCompactResult] = useState<string | null>(null)
  const [verifyResult, setVerifyResult] = useState<string | null>(null)

  const fetchAll = async () => {
    setLoading(true)
    try {
      const [c, s, p, pl] = await Promise.all([
        api.config.export().catch(() => null),
        api.stats.get().catch(() => null),
        api.pool.health().catch(() => []),
        api.plugins.list().catch(() => []),
      ])
      setConfig(c)
      setStats(s)
      setPoolHealth(Array.isArray(p) ? p : [])
      setPlugins(Array.isArray(pl) ? pl : [])
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAll()
  }, [])

  const handleCompact = async () => {
    try {
      const res = await api.audit.compact()
      setCompactResult(`Removed ${res.removed} old log files`)
      setTimeout(() => setCompactResult(null), 5000)
    } catch (err) {
      setCompactResult(`Error: ${err instanceof Error ? err.message : 'Compaction failed'}`)
    }
  }

  const handleVerify = async () => {
    try {
      const res = await api.audit.verify()
      setVerifyResult(
        res.valid
          ? `Hash chain valid (${res.checked_files} files checked)`
          : `Hash chain broken: ${res.errors?.join(', ') || 'unknown error'}`
      )
      setTimeout(() => setVerifyResult(null), 5000)
    } catch (err) {
      setVerifyResult(`Error: ${err instanceof Error ? err.message : 'Verification failed'}`)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-argus-accent animate-spin" />
      </div>
    )
  }

  const handleUpdateToken = async () => {
    if (!tokenInput.trim()) return
    setTokenErr(null)
    setTokenMsg(null)
    try {
      const res = await fetch('/api/stats', {
        headers: { Authorization: `Bearer ${tokenInput.trim()}` },
      })
      if (!res.ok) throw new Error('Token rejected by server')
      saveToken(tokenInput.trim())
      setTokenInput('')
      setTokenMsg('Token updated successfully')
      setTimeout(() => setTokenMsg(null), 3000)
    } catch (err) {
      setTokenErr(err instanceof Error ? err.message : 'Failed to validate token')
    }
  }

  const handleClearToken = () => {
    clearToken()
    setTokenMsg('Token cleared — page will reload')
    setTimeout(() => window.location.reload(), 1500)
  }

  return (
    <div className="space-y-6">
      {/* Token Management */}
      <div>
        <h2 className="text-sm font-semibold text-argus-text uppercase tracking-wider mb-3 flex items-center gap-2">
          <Key className="w-4 h-4" /> API Authentication
        </h2>
        <div className="card">
          <div className="text-xs text-argus-muted mb-3">
            Current token: <code className="text-argus-accent">
              {getToken() ? `${getToken()!.substring(0, 16)}...` : 'none'}
            </code>
          </div>
          <div className="flex gap-3 items-end">
            <div className="flex-1">
              <label className="block text-xs text-argus-muted mb-1">New Token</label>
              <input
                type="password"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                className="input"
                placeholder="Paste new admin token"
              />
            </div>
            <button onClick={handleUpdateToken} className="btn-primary btn-sm" disabled={!tokenInput.trim()}>
              Update
            </button>
            <button onClick={handleClearToken} className="btn-danger btn-sm">
              <LogOut className="w-4 h-4 mr-1" /> Clear
            </button>
          </div>
          {tokenMsg && <div className="mt-2 text-sm text-argus-success">{tokenMsg}</div>}
          {tokenErr && <div className="mt-2 text-sm text-argus-danger">{tokenErr}</div>}
        </div>
      </div>

      {/* Runtime Stats */}
      <div>
        <h2 className="text-sm font-semibold text-argus-text uppercase tracking-wider mb-3 flex items-center gap-2">
          <Activity className="w-4 h-4" /> Runtime Stats
        </h2>
        {stats && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="card">
              <div className="text-sm text-argus-muted">Memory</div>
              <div className="text-xl font-bold">{stats.memory_mb?.toFixed(1) || '-'} MB</div>
            </div>
            <div className="card">
              <div className="text-sm text-argus-muted">Goroutines</div>
              <div className="text-xl font-bold">{stats.goroutines || '-'}</div>
            </div>
            <div className="card">
              <div className="text-sm text-argus-muted">Uptime</div>
              <div className="text-xl font-bold">{stats.uptime_seconds ? `${Math.floor(stats.uptime_seconds / 3600)}h` : '-'}</div>
            </div>
            <div className="card">
              <div className="text-sm text-argus-muted">Total Commands</div>
              <div className="text-xl font-bold">{stats.total_commands || 0}</div>
            </div>
          </div>
        )}
      </div>

      {/* Pool Health */}
      {poolHealth.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-argus-text uppercase tracking-wider mb-3 flex items-center gap-2">
            <Server className="w-4 h-4" /> Pool Health
          </h2>
          <div className="card overflow-x-auto p-0">
            <table className="w-full">
              <thead>
                <tr className="border-b border-argus-border">
                  <th className="table-header">Target</th>
                  <th className="table-header">Status</th>
                  <th className="table-header">Active</th>
                  <th className="table-header">Idle</th>
                  <th className="table-header">Max</th>
                  <th className="table-header">Circuit</th>
                  <th className="table-header">Wait Count</th>
                </tr>
              </thead>
              <tbody>
                {poolHealth.map((p, i) => (
                  <tr key={i} className="hover:bg-argus-bg/50">
                    <td className="table-cell font-medium">{p.target}</td>
                    <td className="table-cell">
                      <span className={`badge ${p.healthy ? 'badge-ok' : 'badge-err'}`}>
                        {p.healthy ? 'Healthy' : 'Down'}
                      </span>
                    </td>
                    <td className="table-cell">{p.active}</td>
                    <td className="table-cell">{p.idle}</td>
                    <td className="table-cell">{p.max}</td>
                    <td className="table-cell">
                      <span className={`badge ${
                        p.circuit_state === 'closed' ? 'badge-ok' :
                        p.circuit_state === 'half-open' ? 'badge-warn' : 'badge-err'
                      }`}>{p.circuit_state}</span>
                    </td>
                    <td className="table-cell">{p.wait_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Audit Tools */}
      <div>
        <h2 className="text-sm font-semibold text-argus-text uppercase tracking-wider mb-3 flex items-center gap-2">
          <HardDrive className="w-4 h-4" /> Audit Maintenance
        </h2>
        <div className="card">
          <div className="flex flex-wrap gap-3">
            <button onClick={handleCompact} className="btn-primary">
              <Download className="w-4 h-4 mr-2" />
              Compact Logs
            </button>
            <button onClick={handleVerify} className="btn-ghost">
              <ShieldCheck className="w-4 h-4 mr-2" />
              Verify Hash Chain
            </button>
          </div>
          {compactResult && (
            <div className={`mt-3 text-sm ${compactResult.startsWith('Error') ? 'text-argus-danger' : 'text-argus-success'}`}>
              {compactResult}
            </div>
          )}
          {verifyResult && (
            <div className={`mt-3 text-sm ${verifyResult.startsWith('Error') ? 'text-argus-danger' : 'text-argus-success'}`}>
              {verifyResult}
            </div>
          )}
        </div>
      </div>

      {/* Plugins */}
      {plugins.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-argus-text uppercase tracking-wider mb-3">Plugins</h2>
          <div className="card overflow-x-auto p-0">
            <table className="w-full">
              <thead>
                <tr className="border-b border-argus-border">
                  <th className="table-header">Name</th>
                  <th className="table-header">Type</th>
                  <th className="table-header">Description</th>
                </tr>
              </thead>
              <tbody>
                {plugins.map((p, i) => (
                  <tr key={i} className="hover:bg-argus-bg/50">
                    <td className="table-cell font-medium">{p.name}</td>
                    <td className="table-cell">
                      <span className="badge-info">{p.type}</span>
                    </td>
                    <td className="table-cell text-argus-muted text-xs">{p.description || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Config */}
      {config && (
        <div>
          <h2 className="text-sm font-semibold text-argus-text uppercase tracking-wider mb-3 flex items-center gap-2">
            <Settings className="w-4 h-4" /> Current Configuration
          </h2>
          <div className="card">
            <pre className="bg-argus-bg rounded-lg p-4 text-xs font-mono overflow-x-auto max-h-96">
              {JSON.stringify(config, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}
