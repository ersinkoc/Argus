import { useEffect, useState } from 'react'
import { FileSearch, Search, Download, RotateCcw, RefreshCw, Shield } from 'lucide-react'
import { api, type AuditEvent, type Fingerprint } from '@/lib/api'
import { timeAgo } from '@/lib/utils'

type Tab = 'search' | 'fingerprints' | 'replay'

export function AuditPage() {
  const [tab, setTab] = useState<Tab>('search')
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [fingerprints, setFingerprints] = useState<Fingerprint[]>([])
  const [loading, setLoading] = useState(false)
  const [searchUsername, setSearchUsername] = useState('')
  const [searchAction, setSearchAction] = useState('')
  const [searchCommand, setSearchCommand] = useState('')
  const [limit, setLimit] = useState('50')
  const [replaySessionId, setReplaySessionId] = useState('')
  const [replayEvents, setReplayEvents] = useState<AuditEvent[]>([])

  const handleSearch = async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = { limit }
      if (searchUsername) params.username = searchUsername
      if (searchAction) params.action = searchAction
      if (searchCommand) params.command_type = searchCommand
      const data = await api.audit.search(params)
      setEvents(Array.isArray(data) ? data : [])
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  const handleFingerprints = async () => {
    setLoading(true)
    try {
      const data = await api.audit.fingerprints(parseInt(limit) || 20)
      setFingerprints(Array.isArray(data) ? data : [])
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  const handleReplay = async () => {
    if (!replaySessionId) return
    setLoading(true)
    try {
      const data = await api.audit.replay(replaySessionId)
      setReplayEvents(Array.isArray(data) ? data : [])
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (tab === 'search') handleSearch()
    else if (tab === 'fingerprints') handleFingerprints()
  }, [tab])

  const handleExport = async () => {
    try {
      const params: Record<string, string> = {}
      if (searchUsername) params.username = searchUsername
      const data = await api.audit.export_audit(params)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `argus-audit-${new Date().toISOString().split('T')[0]}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('Export failed')
    }
  }

  return (
    <div className="space-y-4">
      {/* Tabs */}
      <div className="flex gap-1 bg-argus-card rounded-lg p-1 w-fit">
        {(['search', 'fingerprints', 'replay'] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              tab === t
                ? 'bg-argus-accent text-white'
                : 'text-argus-muted hover:text-argus-text'
            }`}
          >
            {t === 'search' ? 'Search' : t === 'fingerprints' ? 'Fingerprints' : 'Replay'}
          </button>
        ))}
      </div>

      {/* Search */}
      {tab === 'search' && (
        <>
          <div className="card">
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
              <div>
                <label className="block text-xs text-argus-muted mb-1">Username</label>
                <input
                  type="text"
                  value={searchUsername}
                  onChange={(e) => setSearchUsername(e.target.value)}
                  className="input"
                  placeholder="Filter by user"
                />
              </div>
              <div>
                <label className="block text-xs text-argus-muted mb-1">Action</label>
                <select
                  value={searchAction}
                  onChange={(e) => setSearchAction(e.target.value)}
                  className="select"
                >
                  <option value="">All</option>
                  <option value="allow">Allow</option>
                  <option value="block">Block</option>
                  <option value="mask">Mask</option>
                  <option value="approve">Approve</option>
                  <option value="deny">Deny</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-argus-muted mb-1">Command</label>
                <select
                  value={searchCommand}
                  onChange={(e) => setSearchCommand(e.target.value)}
                  className="select"
                >
                  <option value="">All</option>
                  <option value="SELECT">SELECT</option>
                  <option value="INSERT">INSERT</option>
                  <option value="UPDATE">UPDATE</option>
                  <option value="DELETE">DELETE</option>
                  <option value="DDL">DDL</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-argus-muted mb-1">Limit</label>
                <input
                  type="number"
                  value={limit}
                  onChange={(e) => setLimit(e.target.value)}
                  className="input"
                  min={1}
                  max={1000}
                />
              </div>
            </div>
            <div className="flex gap-2 mt-4">
              <button onClick={handleSearch} className="btn-primary" disabled={loading}>
                <Search className="w-4 h-4 mr-2" />
                Search
              </button>
              <button onClick={handleExport} className="btn-ghost">
                <Download className="w-4 h-4 mr-2" />
                Export
              </button>
            </div>
          </div>

          {loading ? (
            <div className="flex justify-center py-8">
              <RefreshCw className="w-6 h-6 text-argus-accent animate-spin" />
            </div>
          ) : events.length === 0 ? (
            <div className="card text-center py-8 text-argus-muted text-sm">
              No audit events found
            </div>
          ) : (
            <div className="card overflow-x-auto p-0">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-argus-border">
                    <th className="table-header">Time</th>
                    <th className="table-header">User</th>
                    <th className="table-header">Action</th>
                    <th className="table-header">Command</th>
                    <th className="table-header">SQL</th>
                    <th className="table-header">Duration</th>
                    <th className="table-header">Rows</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e, i) => (
                    <tr key={e.id || i} className="hover:bg-argus-bg/50">
                      <td className="table-cell text-xs text-argus-muted">{timeAgo(e.timestamp)}</td>
                      <td className="table-cell">{e.username || '-'}</td>
                      <td className="table-cell">
                        <span className={`badge ${
                          e.action === 'block' ? 'badge-err' :
                          e.action === 'mask' ? 'badge-warn' :
                          e.action === 'allow' ? 'badge-ok' :
                          'badge-info'
                        }`}>{e.action}</span>
                      </td>
                      <td className="table-cell font-mono text-xs">{e.command || e.event_type || '-'}</td>
                      <td className="table-cell max-w-xs truncate text-xs text-argus-muted">
                        {e.sql || e.command || '-'}
                      </td>
                      <td className="table-cell text-xs text-argus-muted">
                        {e.duration_us ? `${(e.duration_us / 1000).toFixed(1)}ms` : '-'}
                      </td>
                      <td className="table-cell">{e.rows ?? '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* Fingerprints */}
      {tab === 'fingerprints' && (
        <>
          {loading ? (
            <div className="flex justify-center py-8">
              <RefreshCw className="w-6 h-6 text-argus-accent animate-spin" />
            </div>
          ) : fingerprints.length === 0 ? (
            <div className="card text-center py-8 text-argus-muted text-sm">
              No fingerprints available
            </div>
          ) : (
            <div className="card overflow-x-auto p-0">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-argus-border">
                    <th className="table-header">#</th>
                    <th className="table-header">Count</th>
                    <th className="table-header">Fingerprint</th>
                    <th className="table-header">Sample SQL</th>
                    <th className="table-header">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {fingerprints.map((f, i) => (
                    <tr key={i} className="hover:bg-argus-bg/50">
                      <td className="table-cell text-argus-muted">{i + 1}</td>
                      <td className="table-cell font-bold">{f.count}</td>
                      <td className="table-cell font-mono text-xs max-w-xs truncate">{f.fingerprint}</td>
                      <td className="table-cell text-xs text-argus-muted max-w-sm truncate">{f.sample_sql}</td>
                      <td className="table-cell text-xs text-argus-muted">{timeAgo(f.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* Replay */}
      {tab === 'replay' && (
        <>
          <div className="card">
            <div className="flex gap-4 items-end">
              <div className="flex-1">
                <label className="block text-xs text-argus-muted mb-1">Session ID</label>
                <input
                  type="text"
                  value={replaySessionId}
                  onChange={(e) => setReplaySessionId(e.target.value)}
                  className="input"
                  placeholder="Full session ID"
                />
              </div>
              <button onClick={handleReplay} className="btn-primary" disabled={loading || !replaySessionId}>
                <RotateCcw className="w-4 h-4 mr-2" />
                Replay
              </button>
            </div>
          </div>

          {replayEvents.length > 0 && (
            <div className="card overflow-x-auto p-0">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-argus-border">
                    <th className="table-header">#</th>
                    <th className="table-header">Time</th>
                    <th className="table-header">Action</th>
                    <th className="table-header">SQL</th>
                  </tr>
                </thead>
                <tbody>
                  {replayEvents.map((e, i) => (
                    <tr key={i} className="hover:bg-argus-bg/50">
                      <td className="table-cell text-argus-muted">{i + 1}</td>
                      <td className="table-cell text-xs text-argus-muted">{timeAgo(e.timestamp)}</td>
                      <td className="table-cell">
                        <span className={`badge ${
                          e.action === 'block' ? 'badge-err' : e.action === 'mask' ? 'badge-warn' : 'badge-ok'
                        }`}>{e.action}</span>
                      </td>
                      <td className="table-cell text-xs font-mono max-w-lg truncate">{e.sql || e.command}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  )
}
