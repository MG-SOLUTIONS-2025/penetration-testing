import type { Finding } from "../api/client";

interface Props {
  findings: Finding[];
}

export default function FindingsTable({ findings }: Props) {
  if (findings.length === 0) {
    return <p style={{ color: "var(--text-dim)", padding: 20 }}>No findings yet.</p>;
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Title</th>
          <th>Type</th>
          <th>Target</th>
          <th>Date</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => (
          <tr key={f.id}>
            <td>
              <span className={`severity-badge severity-${f.severity}`}>
                {f.severity}
              </span>
            </td>
            <td style={{ maxWidth: 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {f.title}
            </td>
            <td style={{ color: "var(--text-dim)", fontSize: 13 }}>{f.finding_type}</td>
            <td style={{ fontFamily: "monospace", fontSize: 13 }}>{f.target_value}</td>
            <td style={{ color: "var(--text-dim)", fontSize: 13 }}>
              {new Date(f.created_at).toLocaleDateString()}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
