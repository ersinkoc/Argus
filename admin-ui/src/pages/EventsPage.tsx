import { useState } from 'react'
import { Activity, Play, Pause, Trash2 } from 'lucide-react'
import { useWebSocket, type LiveEvent } from '@/hooks/useWebSocket'

export function EventsPage() {
  const { events, connected, clearEvents } = useWebSocket()
  const [paused, setPaused] = useState(false)
  const [filter, setFilter] = useState<string>('all')
  const [displayed, setDisplayed] = useState<LiveEvent[]>([])

  // Update displayed events (respecting pause + filter)
  if (!paused) {
    const filtered = filter === 'all'
      ? events
      : events.filter((e) => e.type === filter || e.action === filter)
    if (filtered !== displayed) {
      // Use setTimeout to avoid setState during render
      setTimeout(() => setDisplayed(filtered), 0)
    }
  }

  const getEventColor = (e: LiveEvent): string => {
    if (e.action === 'block') return 'text-red-400'
    if (e.action === 'mask') return 'text-amber-400'
    if (e.type === 'anomaly') return 'text-amber-300'
    if (e.type === 'high_cost_query') return 'text-red-300'
    if (e.type === 'query_rewrite') return 'text-purple-400'
    if (e.action === 'allow') return 'text-emerald-400'
    return 'text-blue-400'
  }

  const formatEvent = (e: LiveEvent): string => {
    const ts = new Date().toLocaleTimeString()
    if (e.type === 'command') {
      return `${ts} [${e.action}] ${e.username}@${e.database} ${e.command} (${e.rows || 0} rows, ${e.duration_us ? ((e.duration_us / 1000).toFixed(1)) : '0'}ms)`
    }
    if (e.type === 'anomaly') {
      return `${ts} ⚠ ANOMALY ${JSON.stringify(e.alert)}`
    }
    if (e.type === 'high_cost_query') {
      return `${ts} ⚠ HIGH COST ${e.username} cost=${e.cost}`
    }
    if (e.type === 'query_rewrite') {
      return `${ts} ✏ REWRITE ${e.username} ${JSON.stringify(e.rewrites)}`
    }
    return `${ts} ${JSON.stringify(e)}`
  }

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="card">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${connected ? 'bg-argus-success' : 'bg-argus-danger'}`} />
            <span className="text-sm">{connected ? 'Connected' : 'Disconnected'}</span>
          </div>

          <button
            onClick={() => setPaused(!paused)}
            className={`btn-sm ${paused ? 'btn-warning' : 'btn-ghost'}`}
          >
            {paused ? <Play className="w-4 h-4 mr-1" /> : <Pause className="w-4 h-4 mr-1" />}
            {paused ? 'Resume' : 'Pause'}
          </button>

          <button onClick={clearEvents} className="btn-ghost btn-sm">
            <Trash2 className="w-4 h-4 mr-1" />
            Clear
          </button>

          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="select text-sm py-1.5 w-auto"
          >
            <option value="all">All Events</option>
            <option value="command">Commands</option>
            <option value="allow">Allowed</option>
            <option value="block">Blocked</option>
            <option value="mask">Masked</option>
            <option value="anomaly">Anomalies</option>
            <option value="high_cost_query">High Cost</option>
            <option value="query_rewrite">Rewrites</option>
          </select>

          <span className="text-sm text-argus-muted ml-auto">
            {displayed.length} events
          </span>
        </div>
      </div>

      {/* Event Stream */}
      {displayed.length === 0 ? (
        <div className="card text-center py-12">
          <Activity className="w-12 h-12 text-argus-muted mx-auto mb-4" />
          <p className="text-argus-muted">
            {connected ? 'Waiting for events...' : 'Not connected to event stream'}
          </p>
          <p className="text-xs text-argus-muted mt-2">
            Events appear here in real-time as they flow through Argus
          </p>
        </div>
      ) : (
        <div
          className="card p-0 overflow-hidden"
          style={{ maxHeight: 'calc(100vh - 280px)' }}
        >
          <div className="overflow-y-auto h-full p-3 font-mono text-xs space-y-0.5">
            {displayed.map((e, i) => (
              <div
                key={i}
                className={`${getEventColor(e)} hover:bg-argus-bg/50 rounded px-2 py-1 transition-colors`}
              >
                {formatEvent(e)}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
