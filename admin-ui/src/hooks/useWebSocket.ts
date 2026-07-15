import { useEffect, useRef, useCallback, useState } from 'react'

export interface LiveEvent {
  type: string
  action?: string
  username?: string
  database?: string
  command?: string
  rows?: number
  duration_us?: number
  cost?: number
  risk_level?: string
  alert?: unknown
  rewrites?: unknown
  [key: string]: unknown
}

export function useWebSocket() {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>()
  const reconnectAttempt = useRef(0)

  const connect = useCallback(() => {
    const token = localStorage.getItem('argus_admin_token')
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    // Connect WITHOUT token in URL — it would be logged by proxies.
    // Auth is handled via first-frame authentication.
    const url = `${protocol}//${host}/api/events/ws`

    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      // Send auth token as the very first frame (first-frame auth).
      // This avoids putting the token in the URL query string where
      // proxies, load balancers, and server access logs could record it.
      if (token) {
        ws.send(JSON.stringify({ type: 'auth', token }))
      }
      setConnected(true)
      reconnectAttempt.current = 0
    }

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as LiveEvent
        // Skip auth-response frames (not real events)
        if (data.type === 'auth_ok') return
        setEvents((prev) => [data, ...prev].slice(0, 500))
      } catch {
        // ignore parse errors
      }
    }

    ws.onclose = () => {
      setConnected(false)
      wsRef.current = null
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempt.current), 10000)
      reconnectAttempt.current++
      reconnectTimer.current = setTimeout(connect, delay)
    }

    ws.onerror = () => {
      ws.close()
    }
  }, [])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      if (wsRef.current) wsRef.current.close()
    }
  }, [connect])

  return { events, connected, clearEvents: () => setEvents([]) }
}
