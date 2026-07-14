import { useEffect, useState, useCallback } from 'react'
import { Terminal, RefreshCw, XCircle, Search } from 'lucide-react'
import { api, type Session } from '@/lib/api'

export function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [killing, setKilling] = useState<string | null>(null)

  const fetchSessions = useCallback(async () => {
    try {
      const data = await api.sessions.list()
      setSessions(Array.isArray(data) ? data : [])
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchSessions()
    const interval = setInterval(fetchSessions, 3000)
    return () => clearInterval(interval)
  }, [fetchSessions])

  const handleKill = async (id: string) => {
    if (!confirm('Kill this session?')) return
    setKilling(id)
    try {
      await api.sessions.kill(id)
      setSessions((prev) => prev.filter((s) => s.id !== id))
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to kill session')
    } finally {
      setKilling(null)
    }
  }

  const filtered = sessions.filter((s) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      s.id.toLowerCase().includes(q) ||
      s.username.toLowerCase().includes(q) ||
      (s.database || '').toLowerCase().includes(q) ||
      (s.target || '').toLowerCase().includes(q) ||
      (s.client_ip || '').includes(q)
    )
  })

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-argus-accent animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-argus-muted" />
          <input
            type="text"
            placeholder="Search sessions..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input pl-10"
          />
        </div>
        <button onClick={fetchSessions} className="btn-ghost">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </button>
        <span className="text-sm text-argus-muted">{filtered.length} sessions</span>
      </div>

      {filtered.length === 0 ? (
        <div className="card text-center py-12">
          <Terminal className="w-12 h-12 text-argus-muted mx-auto mb-4" />
          <p className="text-argus-muted">No active sessions</p>
        </div>
      ) : (
        <div className="card overflow-x-auto p-0">
          <table className="w-full">
            <thead>
              <tr className="border-b border-argus-border">
                <th className="table-header">Session ID</th>
                <th className="table-header">User</th>
                <th className="table-header">Database</th>
                <th className="table-header">Client IP</th>
                <th className="table-header">Duration</th>
                <th className="table-header">Commands</th>
                <th className="table-header">Idle</th>
                <th className="table-header">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((s) => (
                <tr key={s.id} className="hover:bg-argus-bg/50">
                  <td className="table-cell font-mono text-xs">{s.id.substring(0, 8)}...</td>
                  <td className="table-cell font-medium">{s.username}</td>
                  <td className="table-cell text-argus-muted">{s.database || '-'}</td>
                  <td className="table-cell text-argus-muted font-mono text-xs">{s.client_ip || '-'}</td>
                  <td className="table-cell">{s.duration}</td>
                  <td className="table-cell">{s.command_count}</td>
                  <td className="table-cell">
                    <span className={s.idle_duration ? 'text-argus-muted' : 'text-argus-muted'}>
                      {s.idle_duration || '-'}
                    </span>
                  </td>
                  <td className="table-cell">
                    <button
                      onClick={() => handleKill(s.id)}
                      disabled={killing === s.id}
                      className="btn-ghost btn-sm text-argus-danger hover:text-red-400"
                    >
                      <XCircle className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
