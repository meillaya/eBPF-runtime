// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Route table. Every console route sits behind RequireRole with the
// minimum role from rbac.rs (all browsable routes = viewer/Read);
// mutations are gated inside their views (analyst=Write,
// policy-admin=Admin). /callback is outside the shell by design.
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthProvider";
import { RequireRole } from "./auth/RequireRole";
import { ErrorBoundary } from "./ui/ErrorBoundary";
import { AgentsView } from "./views/AgentsView";
import { AlertsView } from "./views/AlertsView";
import { CallbackPage } from "./views/CallbackPage";
import { DnsView } from "./views/DnsView";
import { DropsView } from "./views/DropsView";
import { EventsView } from "./views/EventsView";
import { FilesView } from "./views/FilesView";
import { OverviewView } from "./views/OverviewView";
import { PoliciesView } from "./views/PoliciesView";
import { ProcessTreeView } from "./views/ProcessTreeView";
import { RolloutView } from "./views/RolloutView";
import { RulesView } from "./views/RulesView";
import { Shell } from "./views/Shell";
import { SocketsView } from "./views/SocketsView";
import { NotFoundView } from "./views/StaticPages";
import { SyscallView } from "./views/SyscallView";

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ErrorBoundary scope="application shell">
          <Routes>
            <Route path="/callback" element={<CallbackPage />} />
            <Route element={<Shell />}>
              <Route
                path="/"
                element={
                  <RequireRole min="viewer">
                    <OverviewView />
                  </RequireRole>
                }
              />
              <Route
                path="/events"
                element={
                  <RequireRole min="viewer">
                    <EventsView />
                  </RequireRole>
                }
              />
              <Route
                path="/sockets"
                element={
                  <RequireRole min="viewer">
                    <SocketsView />
                  </RequireRole>
                }
              />
              <Route
                path="/dns"
                element={
                  <RequireRole min="viewer">
                    <DnsView />
                  </RequireRole>
                }
              />
              <Route
                path="/files"
                element={
                  <RequireRole min="viewer">
                    <FilesView />
                  </RequireRole>
                }
              />
              <Route
                path="/syscalls"
                element={
                  <RequireRole min="viewer">
                    <SyscallView />
                  </RequireRole>
                }
              />
              <Route
                path="/processes"
                element={
                  <RequireRole min="viewer">
                    <ProcessTreeView />
                  </RequireRole>
                }
              />
              <Route
                path="/alerts"
                element={
                  <RequireRole min="viewer">
                    <AlertsView />
                  </RequireRole>
                }
              />
              <Route
                path="/drops"
                element={
                  <RequireRole min="viewer">
                    <DropsView />
                  </RequireRole>
                }
              />
              <Route
                path="/rules"
                element={
                  <RequireRole min="viewer">
                    <RulesView />
                  </RequireRole>
                }
              />
              <Route
                path="/policies"
                element={
                  <RequireRole min="viewer">
                    <PoliciesView />
                  </RequireRole>
                }
              />
              <Route
                path="/rollout"
                element={
                  <RequireRole min="viewer">
                    <RolloutView />
                  </RequireRole>
                }
              />
              <Route
                path="/agents"
                element={
                  <RequireRole min="viewer">
                    <AgentsView />
                  </RequireRole>
                }
              />
              <Route path="*" element={<NotFoundView />} />
            </Route>
          </Routes>
        </ErrorBoundary>
      </AuthProvider>
    </BrowserRouter>
  );
}
