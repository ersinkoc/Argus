const API_BASE = ''

interface RequestOptions {
  method?: string
  body?: unknown
  headers?: Record<string, string>
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const token = localStorage.getItem('argus_admin_token')
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options.headers,
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  })

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: { message: res.statusText } }))
    throw new Error(error.error?.message || `HTTP ${res.status}`)
  }

  if (res.status === 204) return undefined as T
  return res.json()
}

export interface HealthResponse {
  status: string
  uptime: string
  version: string
  pools: Record<string, {
    Healthy: boolean
    Target: string
    Active: number
    Idle: number
    Max: number
  }>
}

export interface DashboardResponse {
  overview: {
    active_sessions: number
    uptime: string
    memory_mb: number
  }
  traffic: {
    total_commands: number
    blocked_commands: number
    masked_results: number
    total_connections: number
    total_rows: number
  }
  pool: {
    active_connections: number
    idle_connections: number
    total_pools: number
  }
}

export interface Session {
  id: string
  username: string
  database: string
  client_ip: string
  duration: string              // Go time.Duration string, e.g. "5m30s"
  command_count: number
  bytes_in: number
  bytes_out: number
  idle_duration: string         // Go time.Duration string
  roles: string[]
  auth_method?: string
  parameters?: Record<string, string>
}

export interface Approval {
  id: string
  username: string
  database: string
  sql: string
  risk_level: string
  reason: string
  created_at: string
}

export interface AuditEvent {
  id: string
  timestamp: string
  event_type: string
  action: string
  username: string
  database: string
  command: string
  sql: string
  risk_level: string
  duration_us: number
  rows: number
  target: string
  session_id: string
}

export interface Fingerprint {
  fingerprint: string
  count: number
  last_seen: string
  sample_sql: string
}

export interface PolicyInfo {
  name: string
  match: Record<string, unknown>
  action: string
  reason?: string
}

export interface StatsResponse {
  memory_mb: number
  goroutines: number
  uptime_seconds: number
  total_connections: number
  active_sessions: number
  total_commands: number
  blocked_commands: number
  command_counts: Record<string, number>
}

export interface PoolHealth {
  target: string
  healthy: boolean
  active: number
  idle: number
  max: number
  acquired_total: number
  released_total: number
  wait_count: number
  circuit_state: string
}

export interface ConfigExport {
  server?: unknown
  targets?: unknown
  policy?: unknown
  pool?: unknown
  audit?: unknown
  admin?: unknown
}

export interface PluginInfo {
  name: string
  type: string
  description: string
}

export interface Classification {
  level: string
  score: number
  rules: string[]
}

// API functions
export const api = {
  health: {
    get: () => request<HealthResponse>('/healthz'),
    deep: () => request<PoolHealth[]>('/api/health/deep'),
    ready: () => request<{ status: string }>('/readyz'),
  },

  dashboard: {
    get: () => request<DashboardResponse>('/api/dashboard'),
  },

  sessions: {
    list: () => request<Session[]>('/api/sessions'),
    kill: (id: string) => request<void>(`/api/sessions/kill?id=${id}`, { method: 'POST' }),
  },

  policies: {
    list: () => request<PolicyInfo[]>('/api/policies'),
    reload: () => request<{ status: string }>('/api/policies/reload', { method: 'POST' }),
    validate: () => request<{ valid: boolean; issues: Array<{ level: string; message: string }> }>('/api/policies/validate'),
    dryRun: (username: string, sql: string) =>
      request<{ action: string; matched_policy?: string; reason?: string }>(
        '/api/policies/dryrun', { method: 'POST', body: { username, sql } }
      ),
  },

  approvals: {
    list: () => request<Approval[]>('/api/approvals'),
    approve: (id: string) => request<void>(`/api/approvals/approve?id=${id}`, { method: 'POST' }),
    deny: (id: string, reason?: string) =>
      request<void>(`/api/approvals/deny?id=${id}${reason ? `&reason=${encodeURIComponent(reason)}` : ''}`, { method: 'POST' }),
  },

  audit: {
    search: (params: Record<string, string>) => {
      const qs = new URLSearchParams(params).toString()
      return request<AuditEvent[]>(`/api/audit/search?${qs}`)
    },
    replay: (sessionId: string) => request<AuditEvent[]>(`/api/audit/replay?session_id=${sessionId}`),
    fingerprints: (limit = 20) => request<Fingerprint[]>(`/api/audit/fingerprints?limit=${limit}`),
    export_audit: (params: Record<string, string>) => {
      const qs = new URLSearchParams(params).toString()
      return request<AuditEvent[]>(`/api/audit/export?${qs}`)
    },
    compact: () => request<{ status: string; removed: number }>('/api/audit/compact', { method: 'POST' }),
    verify: () => request<{ valid: boolean; checked_files: number; errors: string[] }>('/api/audit/verify'),
  },

  stats: {
    get: () => request<StatsResponse>('/api/stats'),
  },

  pool: {
    health: () => request<PoolHealth[]>('/api/pool/health'),
  },

  config: {
    export: () => request<ConfigExport>('/api/config/export'),
  },

  classify: {
    run: (sqls: string[]) => request<Classification[]>(`/api/classify?sql=${encodeURIComponent(sqls.join(';'))}`),
  },

  plugins: {
    list: () => request<PluginInfo[]>('/api/plugins'),
  },
}
