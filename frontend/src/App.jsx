import { Navigate, Route, Routes } from "react-router";
import { useAuth } from "./auth";
import Layout from "./components/Layout";
import Analytics from "./pages/Analytics";
import CrossDocument from "./pages/CrossDocument";
import Dashboard from "./pages/Dashboard";
import DocumentScanner from "./pages/DocumentScanner";
import EmailScanner from "./pages/EmailScanner";
import Firewall from "./pages/Firewall";
import History from "./pages/History";
import Login from "./pages/Login";
import Settings from "./pages/Settings";
import TestingLab from "./pages/TestingLab";
import Threats from "./pages/Threats";
import UrlScanner from "./pages/UrlScanner";

function Boot({ children }) {
  return (
    <div className="grid min-h-screen place-items-center">
      <div className="flex items-center gap-3 text-sm text-slate-400">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-cyan-400/40 border-t-cyan-300" />
        Establishing secure session…
      </div>
      <span className="sr-only">{children}</span>
    </div>
  );
}

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <Boot>Loading</Boot>;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  const { user, loading } = useAuth();

  return (
    <Routes>
      <Route path="/login" element={loading ? <Boot>Loading</Boot> : user ? <Navigate to="/" replace /> : <Login />} />
      <Route
        element={
          <Protected>
            <Layout />
          </Protected>
        }
      >
        <Route path="/" element={<Dashboard />} />
        <Route path="/scanner/document" element={<DocumentScanner />} />
        <Route path="/scanner/email" element={<EmailScanner />} />
        <Route path="/scanner/url" element={<UrlScanner />} />
        <Route path="/threats" element={<Threats />} />
        <Route path="/history" element={<History />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/cross-document" element={<CrossDocument />} />
        <Route path="/firewall" element={<Firewall />} />
        <Route path="/testing" element={<TestingLab />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
