import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { getFindings } from "../api/client";
import FindingsTable from "../components/FindingsTable";
import SeverityChart from "../components/SeverityChart";

export default function Findings() {
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ["findings", severity, page],
    queryFn: () => getFindings({ severity: severity || undefined, page }),
  });

  const findings = data?.items || [];
  const totalPages = data ? Math.ceil(data.total / data.page_size) : 0;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h2>Findings</h2>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <span style={{ color: "var(--text-dim)", fontSize: 13 }}>
            {data?.total || 0} total
          </span>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 16 }}>
        <div className="card">
          {isLoading ? (
            <p style={{ color: "var(--text-dim)" }}>Loading...</p>
          ) : (
            <>
              <FindingsTable findings={findings} />
              {totalPages > 1 && (
                <div style={{ display: "flex", justifyContent: "center", gap: 8, marginTop: 16 }}>
                  <button className="btn-ghost" onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1}>
                    Previous
                  </button>
                  <span style={{ padding: "8px 12px", color: "var(--text-dim)", fontSize: 13 }}>
                    Page {page} of {totalPages}
                  </span>
                  <button className="btn-ghost" onClick={() => setPage(page + 1)} disabled={page >= totalPages}>
                    Next
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        <div className="card" style={{ height: "fit-content" }}>
          <h3 style={{ fontSize: 15, marginBottom: 12 }}>By Severity</h3>
          <SeverityChart findings={findings} />
        </div>
      </div>
    </div>
  );
}
