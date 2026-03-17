import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import EngagementDetail from "./pages/EngagementDetail";
import Engagements from "./pages/Engagements";
import Findings from "./pages/Findings";
import Login from "./pages/Login";
import Scans from "./pages/Scans";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem("token");
  if (!token) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route path="/" element={<Dashboard />} />
        <Route path="/engagements" element={<Engagements />} />
        <Route path="/engagements/:id" element={<EngagementDetail />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/findings" element={<Findings />} />
      </Route>
    </Routes>
  );
}
