import { useState, useEffect } from 'react'
import { Eye, Key, AlertTriangle, CheckCircle } from 'lucide-react'

const TOKEN_KEY = 'argus_admin_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

interface TokenGateProps {
  children: React.ReactNode
}

export function TokenGate({ children }: TokenGateProps) {
  const [token, setTokenState] = useState<string>(getToken() || '')
  const [input, setInput] = useState('')
  const [testing, setTesting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [ready, setReady] = useState(!!getToken())

  // Re-check token on mount (in case it was cleared from settings)
  useEffect(() => {
    const t = getToken()
    setReady(!!t)
    if (t) setTokenState(t)
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim()) return

    setTesting(true)
    setError(null)

    // Test the token by calling the stats endpoint
    try {
      const res = await fetch('/api/stats', {
        headers: { Authorization: `Bearer ${input.trim()}` },
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error?.message || `HTTP ${res.status}`)
      }
      setToken(input.trim())
      setTokenState(input.trim())
      setReady(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Token validation failed')
    } finally {
      setTesting(false)
    }
  }

  const handleClear = () => {
    clearToken()
    setTokenState('')
    setInput('')
    setReady(false)
  }

  if (ready) {
    return <>{children}</>
  }

  return (
    <div className="min-h-screen bg-argus-bg flex items-center justify-center p-6">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-argus-accent/10 mb-4">
            <Eye className="w-8 h-8 text-argus-accent" />
          </div>
          <h1 className="text-2xl font-bold text-argus-text">Argus Admin</h1>
          <p className="text-argus-muted text-sm mt-1">Enter your admin token to continue</p>
        </div>

        {/* Token Form */}
        <form onSubmit={handleSubmit} className="card space-y-4">
          <div>
            <label className="block text-sm font-medium text-argus-text mb-2">
              Admin Bearer Token
            </label>
            <div className="relative">
              <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-argus-muted" />
              <input
                type="password"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="input pl-10"
                placeholder="Paste your ARGUS_ADMIN_TOKEN"
                autoFocus
              />
            </div>
            <p className="text-xs text-argus-muted mt-1.5">
              Set via the <code className="text-argus-accent">ARGUS_ADMIN_TOKEN</code> env var when starting Argus.
            </p>
          </div>

          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-900/20 border border-red-900/30">
              <AlertTriangle className="w-4 h-4 text-argus-danger shrink-0 mt-0.5" />
              <span className="text-sm text-argus-danger">{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={testing || !input.trim()}
            className="btn-primary w-full"
          >
            {testing ? 'Validating...' : 'Connect'}
          </button>
        </form>

        {/* Help */}
        <div className="mt-6 p-4 rounded-lg bg-argus-card/50 border border-argus-border text-xs text-argus-muted space-y-2">
          <p className="font-medium text-argus-text text-sm">Where to find your token?</p>
          <p>
            When running Argus, set the <code className="text-argus-accent">ARGUS_ADMIN_TOKEN</code> environment variable:
          </p>
          <pre className="bg-argus-bg rounded p-2 font-mono text-xs">
            docker run -e ARGUS_ADMIN_TOKEN="your-token-here" ...
          </pre>
          <p>
            The token is stored in your browser's localStorage and sent as a Bearer token with every API request.
          </p>
        </div>
      </div>
    </div>
  )
}
