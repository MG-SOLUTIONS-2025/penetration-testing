import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useParams } from "react-router-dom";
import {
  createScan,
  createTarget,
  deleteTarget,
  getScans,
  getTargets,
  type CreateTarget,
} from "../api/client";
import ScanProgress from "../components/ScanProgress";

const SCAN_TYPES = ["nmap", "subfinder", "nuclei", "sslyze", "headers"];

export default function EngagementDetail() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();

  const { data: targets } = useQuery({
    queryKey: ["targets", id],
    queryFn: () => getTargets(id!),
  });
  const { data: scans } = useQuery({
    queryKey: ["scans", id],
    queryFn: () => getScans({ engagement_id: id }),
  });

  const [targetForm, setTargetForm] = useState<CreateTarget>({ target_type: "domain", value: "" });
  const [scanType, setScanType] = useState("nmap");
  const [selectedTarget, setSelectedTarget] = useState("");

  const addTarget = useMutation({
    mutationFn: (data: CreateTarget) => createTarget(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets", id] });
      setTargetForm({ target_type: "domain", value: "" });
    },
  });

  const removeTarget = useMutation({
    mutationFn: (targetId: string) => deleteTarget(id!, targetId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["targets", id] }),
  });

  const startScan = useMutation({
    mutationFn: () =>
      createScan({
        engagement_id: id!,
        target_id: selectedTarget || undefined,
        scan_type: scanType,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans", id] }),
  });

  return (
    <div>
      <h2 style={{ marginBottom: 24 }}>Engagement Details</h2>

      {/* Targets */}
      <div className="card" style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: 15, marginBottom: 16 }}>Targets</h3>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            addTarget.mutate(targetForm);
          }}
          style={{ display: "flex", gap: 8, marginBottom: 16 }}
        >
          <select
            value={targetForm.target_type}
            onChange={(e) => setTargetForm({ ...targetForm, target_type: e.target.value })}
          >
            <option value="domain">Domain</option>
            <option value="ip">IP</option>
            <option value="cidr">CIDR</option>
            <option value="url">URL</option>
          </select>
          <input
            placeholder="e.g. example.com or 10.0.0.0/24"
            value={targetForm.value}
            onChange={(e) => setTargetForm({ ...targetForm, value: e.target.value })}
            style={{ flex: 1 }}
            required
          />
          <button type="submit" className="btn-primary">
            Add Target
          </button>
        </form>

        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>In Scope</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {targets?.map((t) => (
              <tr key={t.id}>
                <td>{t.target_type}</td>
                <td style={{ fontFamily: "monospace" }}>{t.value}</td>
                <td>{t.is_in_scope ? "Yes" : "No"}</td>
                <td>
                  <button className="btn-ghost" style={{ padding: "4px 8px", fontSize: 12 }} onClick={() => removeTarget.mutate(t.id)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Launch Scan */}
      <div className="card" style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: 15, marginBottom: 16 }}>Launch Scan</h3>
        <div style={{ display: "flex", gap: 8 }}>
          <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
            {SCAN_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <select value={selectedTarget} onChange={(e) => setSelectedTarget(e.target.value)}>
            <option value="">Select target...</option>
            {targets?.map((t) => (
              <option key={t.id} value={t.id}>
                {t.value}
              </option>
            ))}
          </select>
          <button className="btn-primary" onClick={() => startScan.mutate()} disabled={!selectedTarget}>
            Start Scan
          </button>
        </div>
      </div>

      {/* Scans */}
      <div className="card">
        <h3 style={{ fontSize: 15, marginBottom: 16 }}>Scans</h3>
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Status</th>
              <th>Progress</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {scans?.map((s) => (
              <tr key={s.id}>
                <td>{s.scan_type}</td>
                <td>
                  <span className={`status-badge status-${s.status}`}>{s.status}</span>
                </td>
                <td style={{ width: 300 }}>
                  {s.status === "running" && s.celery_task_id && (
                    <ScanProgress taskId={s.celery_task_id} scanId={s.id} />
                  )}
                  {s.error_message && (
                    <span style={{ fontSize: 12, color: "var(--critical)" }}>{s.error_message}</span>
                  )}
                </td>
                <td style={{ color: "var(--text-dim)", fontSize: 13 }}>
                  {new Date(s.created_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
