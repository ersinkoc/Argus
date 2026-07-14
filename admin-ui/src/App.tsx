import { useState } from 'react'
import { Layout } from '@/components/Layout'
import { TokenGate } from '@/components/TokenGate'
import { useWebSocket } from '@/hooks/useWebSocket'
import { DashboardPage } from '@/pages/DashboardPage'
import { SessionsPage } from '@/pages/SessionsPage'
import { AuditPage } from '@/pages/AuditPage'
import { PoliciesPage } from '@/pages/PoliciesPage'
import { ApprovalsPage } from '@/pages/ApprovalsPage'
import { EventsPage } from '@/pages/EventsPage'
import { SettingsPage } from '@/pages/SettingsPage'

export default function App() {
  const [currentPath, setCurrentPath] = useState('/')
  const { connected } = useWebSocket()

  const renderPage = () => {
    switch (currentPath) {
      case '/':
        return <DashboardPage />
      case '/sessions':
        return <SessionsPage />
      case '/audit':
        return <AuditPage />
      case '/policies':
        return <PoliciesPage />
      case '/approvals':
        return <ApprovalsPage />
      case '/events':
        return <EventsPage />
      case '/settings':
        return <SettingsPage />
      default:
        return (
          <div className="card text-center py-12">
            <p className="text-argus-muted">Page not found</p>
            <button onClick={() => setCurrentPath('/')} className="btn-primary mt-4">
              Go to Dashboard
            </button>
          </div>
        )
    }
  }

  return (
    <TokenGate>
      <Layout
        currentPath={currentPath}
        onNavigate={setCurrentPath}
        wsConnected={connected}
      >
        {renderPage()}
      </Layout>
    </TokenGate>
  )
}
