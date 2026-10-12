import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppLayout } from './components/layout/AppLayout';
import { DashboardPage } from './pages/DashboardPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { NewInvestigationPage } from './pages/NewInvestigationPage';
import { IncidentDetailsPage } from './pages/IncidentDetailsPage';
import { AgentMonitorPage } from './pages/AgentMonitorPage';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage';
import { RecoveryPolicyPage } from './pages/RecoveryPolicyPage';
import { ReportsPage } from './pages/ReportsPage';
import { EvaluationPage } from './pages/EvaluationPage';

const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AppLayout>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/new" element={<NewInvestigationPage />} />
          <Route path="/incidents/:incidentId" element={<IncidentDetailsPage />} />
          <Route path="/agent-monitor" element={<AgentMonitorPage />} />
          <Route path="/threat-intelligence" element={<ThreatIntelligencePage />} />
          <Route path="/recovery-policy" element={<RecoveryPolicyPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/evaluation" element={<EvaluationPage />} />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  );
};

export default App;
