import { useState } from 'react'
import {
  LayoutDashboard,
  Terminal,
  FileSearch,
  Shield,
  CheckSquare,
  Activity,
  Settings,
  Menu,
  X,
  Eye,
} from 'lucide-react'

const NAV_ITEMS = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/sessions', label: 'Sessions', icon: Terminal },
  { path: '/audit', label: 'Audit Log', icon: FileSearch },
  { path: '/policies', label: 'Policies', icon: Shield },
  { path: '/approvals', label: 'Approvals', icon: CheckSquare },
  { path: '/events', label: 'Live Events', icon: Activity },
  { path: '/settings', label: 'Settings', icon: Settings },
]

interface LayoutProps {
  children: React.ReactNode
  currentPath: string
  onNavigate: (path: string) => void
  wsConnected: boolean
}

export function Layout({ children, currentPath, onNavigate, wsConnected }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="min-h-screen flex">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-argus-card border-r border-argus-border transform transition-transform duration-200 ease-in-out lg:translate-x-0 lg:static lg:z-auto ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex items-center justify-between h-16 px-6 border-b border-argus-border">
          <div className="flex items-center gap-3">
            <Eye className="w-7 h-7 text-argus-accent" />
            <span className="text-lg font-bold text-argus-text">Argus</span>
          </div>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden text-argus-muted hover:text-argus-text"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <nav className="p-4 space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon
            const isActive = currentPath === item.path
            return (
              <button
                key={item.path}
                onClick={() => {
                  onNavigate(item.path)
                  setSidebarOpen(false)
                }}
                className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-argus-accent/10 text-argus-accent'
                    : 'text-argus-muted hover:bg-argus-bg hover:text-argus-text'
                }`}
              >
                <Icon className="w-5 h-5" />
                {item.label}
              </button>
            )
          })}
        </nav>

        {/* Version */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-argus-border">
          <div className="flex items-center gap-2 text-xs text-argus-muted">
            <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-argus-success' : 'bg-argus-danger'}`} />
            <span>{wsConnected ? 'WS Connected' : 'WS Disconnected'}</span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-16 border-b border-argus-border flex items-center px-6 bg-argus-card/50 backdrop-blur-sm">
          <button
            onClick={() => setSidebarOpen(true)}
            className="lg:hidden text-argus-muted hover:text-argus-text mr-4"
          >
            <Menu className="w-6 h-6" />
          </button>
          <h1 className="text-lg font-semibold text-argus-text">
            {NAV_ITEMS.find((i) => i.path === currentPath)?.label || 'Argus Admin'}
          </h1>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
