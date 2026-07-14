import { useEffect, useState, useCallback } from 'react'
import { CheckSquare, RefreshCw, CheckCircle, XCircle } from 'lucide-react'
import { api, type Approval } from '@/lib/api'
import { timeAgo } from '@/lib/utils'

export function ApprovalsPage() {
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [loading, setLoading] = useState(true)
  const [actionId, setActionId] = useState<string | null>(null)
  const [denyReason, setDenyReason] = useState('')
  const [denyId, setDenyId] = useState<string | null>(null)

  const fetchApprovals = useCallback(async () => {
    try {
      const data = await api.approvals.list()
      setApprovals(Array.isArray(data) ? data : [])
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchApprovals()
    const interval = setInterval(fetchApprovals, 5000)
    return () => clearInterval(interval)
  }, [fetchApprovals])

  const handleApprove = async (id: string) => {
    setActionId(id)
    try {
      await api.approvals.approve(id)
      setApprovals((prev) => prev.filter((a) => a.id !== id))
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to approve')
    } finally {
      setActionId(null)
    }
  }

  const handleDeny = async (id: string) => {
    setActionId(id)
    try {
      await api.approvals.deny(id, denyReason || 'denied')
      setApprovals((prev) => prev.filter((a) => a.id !== id))
      setDenyId(null)
      setDenyReason('')
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to deny')
    } finally {
      setActionId(null)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-argus-accent animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-sm text-argus-muted">{approvals.length} pending</span>
        </div>
        <button onClick={fetchApprovals} className="btn-ghost">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </button>
      </div>

      {approvals.length === 0 ? (
        <div className="card text-center py-12">
          <CheckSquare className="w-12 h-12 text-argus-muted mx-auto mb-4" />
          <p className="text-argus-muted">No pending approvals</p>
        </div>
      ) : (
        <div className="space-y-3">
          {approvals.map((a) => (
            <div key={a.id} className="card">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-medium text-argus-text">{a.username}</span>
                    <span className="text-argus-muted text-sm">@{a.database}</span>
                    {a.risk_level && (
                      <span className={`badge ${
                        a.risk_level === 'critical' ? 'badge-err' :
                        a.risk_level === 'high' ? 'badge-warn' :
                        'badge-info'
                      }`}>{a.risk_level}</span>
                    )}
                    <span className="text-xs text-argus-muted">{timeAgo(a.created_at)}</span>
                  </div>
                  <pre className="bg-argus-bg rounded-lg p-3 text-xs font-mono overflow-x-auto mb-2">
                    {a.sql}
                  </pre>
                  {a.reason && (
                    <div className="text-xs text-argus-muted">
                      Reason: {a.reason}
                    </div>
                  )}
                </div>
              </div>

              {denyId === a.id ? (
                <div className="flex gap-2 mt-3 items-center">
                  <input
                    type="text"
                    value={denyReason}
                    onChange={(e) => setDenyReason(e.target.value)}
                    className="input flex-1"
                    placeholder="Denial reason..."
                    autoFocus
                  />
                  <button
                    onClick={() => handleDeny(a.id)}
                    disabled={actionId === a.id}
                    className="btn-danger btn-sm"
                  >
                    Confirm Deny
                  </button>
                  <button
                    onClick={() => { setDenyId(null); setDenyReason('') }}
                    className="btn-ghost btn-sm"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <div className="flex gap-2 mt-3">
                  <button
                    onClick={() => handleApprove(a.id)}
                    disabled={actionId === a.id}
                    className="btn-success btn-sm"
                  >
                    <CheckCircle className="w-4 h-4 mr-1" />
                    Approve
                  </button>
                  <button
                    onClick={() => setDenyId(a.id)}
                    disabled={actionId === a.id}
                    className="btn-danger btn-sm"
                  >
                    <XCircle className="w-4 h-4 mr-1" />
                    Deny
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
