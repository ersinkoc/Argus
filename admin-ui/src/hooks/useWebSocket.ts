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
    const url = `${protocol}//${host}/api/events/ws${token ? `?token=${token}` : ''}`

    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      reconnectAttempt.current = 0
    }

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as LiveEvent
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
