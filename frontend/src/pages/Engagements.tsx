import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { createEngagement, getEngagements, type CreateEngagement } from "../api/client";

export default function Engagements() {
  const queryClient = useQueryClient();
  const { data: engagements, isLoading } = useQuery({
    queryKey: ["engagements"],
    queryFn: getEngagements,
  });
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<CreateEngagement>({
    name: "",
    client_name: "",
    authorized_by: "",
    starts_at: new Date().toISOString().slice(0, 16),
    ends_at: new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 16),
  });

  const mutation = useMutation({
    mutationFn: createEngagement,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["engagements"] });
      setShowForm(false);
      setForm({ name: "", client_name: "", authorized_by: "", starts_at: "", ends_at: "" });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate({
      ...form,
      starts_at: new Date(form.starts_at).toISOString(),
      ends_at: new Date(form.ends_at).toISOString(),
    });
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h2>Engagements</h2>
        <button className="btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? "Cancel" : "New Engagement"}
        </button>
      </div>

      {showForm && (
        <div className="card" style={{ marginBottom: 24 }}>
          <form onSubmit={handleSubmit} style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <input placeholder="Engagement name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            <input placeholder="Client name" value={form.client_name} onChange={(e) => setForm({ ...form, client_name: e.target.value })} required />
            <input placeholder="Authorized by (name + title)" value={form.authorized_by} onChange={(e) => setForm({ ...form, authorized_by: e.target.value })} required />
            <div />
            <label style={{ fontSize: 13, color: "var(--text-dim)" }}>
              Starts
              <input type="datetime-local" value={form.starts_at} onChange={(e) => setForm({ ...form, starts_at: e.target.value })} style={{ width: "100%", marginTop: 4 }} required />
            </label>
            <label style={{ fontSize: 13, color: "var(--text-dim)" }}>
              Ends
              <input type="datetime-local" value={form.ends_at} onChange={(e) => setForm({ ...form, ends_at: e.target.value })} style={{ width: "100%", marginTop: 4 }} required />
            </label>
            <div style={{ gridColumn: "1 / -1" }}>
              <button type="submit" className="btn-primary">Create Engagement</button>
            </div>
          </form>
        </div>
      )}

      {isLoading ? (
        <p style={{ color: "var(--text-dim)" }}>Loading...</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Client</th>
              <th>Authorization Window</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {engagements?.map((eng) => {
              const now = new Date();
              const active = now >= new Date(eng.starts_at) && now <= new Date(eng.ends_at);
              return (
                <tr key={eng.id}>
                  <td>
                    <Link to={`/engagements/${eng.id}`}>{eng.name}</Link>
                  </td>
                  <td>{eng.client_name}</td>
                  <td style={{ fontSize: 13, color: "var(--text-dim)" }}>
                    {new Date(eng.starts_at).toLocaleDateString()} - {new Date(eng.ends_at).toLocaleDateString()}
                  </td>
                  <td>
                    <span className={`status-badge ${active ? "status-running" : "status-failed"}`}>
                      {active ? "Active" : "Expired"}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
