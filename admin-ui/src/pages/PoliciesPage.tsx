import { useEffect, useState } from 'react'
import { Shield, RefreshCw, CheckCircle, AlertTriangle, Play } from 'lucide-react'
import { api, type PolicyInfo } from '@/lib/api'

export function PoliciesPage() {
  const [policies, setPolicies] = useState<PolicyInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [validation, setValidation] = useState<{ valid: boolean; issues: Array<{ level: string; message: string }> } | null>(null)
  const [reloadMsg, setReloadMsg] = useState('')
  const [dryRunUser, setDryRunUser] = useState('test_user')
  const [dryRunSql, setDryRunSql] = useState('SELECT * FROM users WHERE id = 1')
  const [dryRunResult, setDryRunResult] = useState<string | null>(null)

  const fetchPolicies = async () => {
    setLoading(true)
    try {
      const data = await api.policies.list()
      setPolicies(Array.isArray(data) ? data : [])
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPolicies()
  }, [])

  const handleReload = async () => {
    try {
      const res = await api.policies.reload()
      setReloadMsg(res.status || 'Policies reloaded')
      setTimeout(() => setReloadMsg(''), 3000)
      fetchPolicies()
    } catch (err) {
      setReloadMsg(err instanceof Error ? err.message : 'Reload failed')
    }
  }

  const handleValidate = async () => {
    try {
      const res = await api.policies.validate()
      setValidation(res)
    } catch (err) {
      setValidation({ valid: false, issues: [{ level: 'error', message: err instanceof Error ? err.message : 'Validation failed' }] })
    }
  }

  const handleDryRun = async () => {
    try {
      const res = await api.policies.dryRun(dryRunUser, dryRunSql)
      setDryRunResult(JSON.stringify(res, null, 2))
    } catch (err) {
      setDryRunResult(`Error: ${err instanceof Error ? err.message : 'Dry run failed'}`)
    }
  }

  const actionCount = (action: string) => policies.filter((p) => p.action === action).length

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="card text-center">
          <div className="text-2xl font-bold text-argus-text">{policies.length}</div>
          <div className="text-sm text-argus-muted">Total Rules</div>
        </div>
        <div className="card text-center">
          <div className="text-2xl font-bold text-argus-danger">{actionCount('block')}</div>
          <div className="text-sm text-argus-muted">Block Rules</div>
        </div>
        <div className="card text-center">
          <div className="text-2xl font-bold text-argus-warning">{actionCount('mask')}</div>
          <div className="text-sm text-argus-muted">Mask Rules</div>
        </div>
      </div>

      {/* Actions */}
      <div className="card">
        <div className="flex flex-wrap gap-3">
          <button onClick={handleReload} className="btn-primary" disabled={loading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Reload Policies
          </button>
          <button onClick={handleValidate} className="btn-ghost">
            <CheckCircle className="w-4 h-4 mr-2" />
            Validate
          </button>
        </div>
        {reloadMsg && (
          <div className="mt-3 text-sm text-argus-success">{reloadMsg}</div>
        )}
      </div>

      {/* Validation Results */}
      {validation && (
        <div className={`card border ${validation.valid ? 'border-argus-success/30' : 'border-argus-danger/30'}`}>
          <div className="flex items-center gap-2 mb-3">
            {validation.valid ? (
              <CheckCircle className="w-5 h-5 text-argus-success" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-argus-warning" />
            )}
            <span className={`font-medium ${validation.valid ? 'text-argus-success' : 'text-argus-warning'}`}>
              {validation.valid ? 'All rules valid' : `${validation.issues.length} issues found`}
            </span>
          </div>
          {validation.issues.length > 0 && (
            <div className="space-y-1">
              {validation.issues.map((issue, i) => (
                <div key={i} className={`text-sm ${issue.level === 'error' ? 'text-argus-danger' : 'text-argus-warning'}`}>
                  [{issue.level}] {issue.message}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Dry Run */}
      <div className="card">
        <h3 className="text-sm font-semibold text-argus-text uppercase tracking-wider mb-3">Policy Dry Run</h3>
        <div className="flex gap-4 mb-3">
          <div className="flex-1">
            <label className="block text-xs text-argus-muted mb-1">Username</label>
            <input
              type="text"
              value={dryRunUser}
              onChange={(e) => setDryRunUser(e.target.value)}
              className="input"
            />
          </div>
          <div className="flex-[2]">
            <label className="block text-xs text-argus-muted mb-1">SQL Query</label>
            <input
              type="text"
              value={dryRunSql}
              onChange={(e) => setDryRunSql(e.target.value)}
              className="input"
              placeholder="SELECT * FROM users"
            />
          </div>
          <div className="flex items-end">
            <button onClick={handleDryRun} className="btn-primary">
              <Play className="w-4 h-4 mr-2" />
              Test
            </button>
          </div>
        </div>
        {dryRunResult && (
          <pre className="bg-argus-bg rounded-lg p-3 text-xs font-mono overflow-x-auto">{dryRunResult}</pre>
        )}
      </div>

      {/* Policy List */}
      {loading ? (
        <div className="flex justify-center py-8">
          <RefreshCw className="w-6 h-6 text-argus-accent animate-spin" />
        </div>
      ) : policies.length === 0 ? (
        <div className="card text-center py-8 text-argus-muted text-sm">
          No policies loaded
        </div>
      ) : (
        <div className="card overflow-x-auto p-0">
          <table className="w-full">
            <thead>
              <tr className="border-b border-argus-border">
                <th className="table-header">Name</th>
                <th className="table-header">Action</th>
                <th className="table-header">Reason</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p, i) => (
                <tr key={i} className="hover:bg-argus-bg/50">
                  <td className="table-cell font-medium">{p.name}</td>
                  <td className="table-cell">
                    <span className={`badge ${
                      p.action === 'block' ? 'badge-err' :
                      p.action === 'mask' ? 'badge-warn' :
                      p.action === 'allow' ? 'badge-ok' :
                      'badge-info'
                    }`}>{p.action}</span>
                  </td>
                  <td className="table-cell text-argus-muted text-xs">{p.reason || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
