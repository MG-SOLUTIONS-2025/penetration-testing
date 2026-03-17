import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";

const NAV_ITEMS = [
  { path: "/", label: "Dashboard", icon: "grid" },
  { path: "/engagements", label: "Engagements", icon: "shield" },
  { path: "/scans", label: "Scans", icon: "search" },
  { path: "/findings", label: "Findings", icon: "alert" },
];

export default function Layout() {
  const location = useLocation();
  const navigate = useNavigate();

  const logout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <aside
        style={{
          width: 220,
          background: "var(--bg-card)",
          borderRight: "1px solid var(--border)",
          padding: "20px 0",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div style={{ padding: "0 20px 24px", borderBottom: "1px solid var(--border)" }}>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: "var(--accent)" }}>
            PenTest
          </h1>
          <span style={{ fontSize: 11, color: "var(--text-dim)" }}>Security Platform</span>
        </div>
        <nav style={{ flex: 1, padding: "12px 8px" }}>
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              style={{
                display: "block",
                padding: "10px 12px",
                borderRadius: 6,
                fontSize: 14,
                color: location.pathname === item.path ? "var(--accent)" : "var(--text-dim)",
                background: location.pathname === item.path ? "var(--bg-hover)" : "transparent",
                marginBottom: 2,
              }}
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <div style={{ padding: "12px 16px", borderTop: "1px solid var(--border)" }}>
          <button className="btn-ghost" style={{ width: "100%", fontSize: 13 }} onClick={logout}>
            Sign Out
          </button>
        </div>
      </aside>
      <main style={{ flex: 1, padding: 32, overflowY: "auto" }}>
        <Outlet />
      </main>
    </div>
  );
}
