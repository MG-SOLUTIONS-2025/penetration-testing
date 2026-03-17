import { useQuery } from "@tanstack/react-query";
import { getFindings, getScans } from "../api/client";
import SeverityChart from "../components/SeverityChart";

export default function Dashboard() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: () => getScans() });
  const { data: findingsData } = useQuery({
    queryKey: ["findings"],
    queryFn: () => getFindings({ page: 1 }),
  });

  const findings = findingsData?.items || [];
  const totalScans = scans?.length || 0;
  const runningScans = scans?.filter((s) => s.status === "running").length || 0;
  const totalFindings = findingsData?.total || 0;
  const criticalFindings = findings.filter((f) => f.severity === "critical").length;

  const stats = [
    { label: "Total Scans", value: totalScans, color: "var(--accent)" },
    { label: "Running", value: runningScans, color: "var(--success)" },
    { label: "Findings", value: totalFindings, color: "var(--medium)" },
    { label: "Critical", value: criticalFindings, color: "var(--critical)" },
  ];

  return (
    <div>
      <h2 style={{ marginBottom: 24 }}>Dashboard</h2>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 32 }}>
        {stats.map((s) => (
          <div key={s.label} className="card">
            <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 4 }}>{s.label}</p>
            <p style={{ fontSize: 28, fontWeight: 700, color: s.color }}>{s.value}</p>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div className="card">
          <h3 style={{ fontSize: 15, marginBottom: 16 }}>Severity Distribution</h3>
          <SeverityChart findings={findings} />
          <div style={{ display: "flex", gap: 12, justifyContent: "center", marginTop: 12 }}>
            {["critical", "high", "medium", "low", "info"].map((sev) => (
              <span key={sev} style={{ fontSize: 11, color: "var(--text-dim)" }}>
                <span className={`severity-badge severity-${sev}`} style={{ marginRight: 4 }}>
                  {sev}
                </span>
                {findings.filter((f) => f.severity === sev).length}
              </span>
            ))}
          </div>
        </div>

        <div className="card">
          <h3 style={{ fontSize: 15, marginBottom: 16 }}>Recent Scans</h3>
          {scans && scans.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 8).map((s) => (
                  <tr key={s.id}>
                    <td>{s.scan_type}</td>
                    <td>
                      <span className={`status-badge status-${s.status}`}>{s.status}</span>
                    </td>
                    <td style={{ color: "var(--text-dim)", fontSize: 13 }}>
                      {new Date(s.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{ color: "var(--text-dim)" }}>No scans yet</p>
          )}
        </div>
      </div>
    </div>
  );
}
