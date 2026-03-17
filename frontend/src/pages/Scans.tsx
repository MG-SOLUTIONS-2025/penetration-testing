import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { getScans } from "../api/client";
import ScanProgress from "../components/ScanProgress";

export default function Scans() {
  const [statusFilter, setStatusFilter] = useState("");
  const { data: scans, isLoading } = useQuery({
    queryKey: ["scans", statusFilter],
    queryFn: () => getScans({ status: statusFilter || undefined }),
    refetchInterval: 5000,
  });

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h2>Scans</h2>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>
      </div>

      {isLoading ? (
        <p style={{ color: "var(--text-dim)" }}>Loading...</p>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Started</th>
                <th>Completed</th>
              </tr>
            </thead>
            <tbody>
              {scans?.map((s) => (
                <tr key={s.id}>
                  <td style={{ fontFamily: "monospace", fontSize: 12 }}>{s.id.slice(0, 8)}</td>
                  <td>{s.scan_type}</td>
                  <td>
                    <span className={`status-badge status-${s.status}`}>{s.status}</span>
                  </td>
                  <td style={{ width: 250 }}>
                    {s.status === "running" && s.celery_task_id && (
                      <ScanProgress taskId={s.celery_task_id} scanId={s.id} />
                    )}
                  </td>
                  <td style={{ color: "var(--text-dim)", fontSize: 13 }}>
                    {s.started_at ? new Date(s.started_at).toLocaleString() : "-"}
                  </td>
                  <td style={{ color: "var(--text-dim)", fontSize: 13 }}>
                    {s.completed_at ? new Date(s.completed_at).toLocaleString() : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
