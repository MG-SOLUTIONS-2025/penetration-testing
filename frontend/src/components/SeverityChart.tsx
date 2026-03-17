import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { Finding } from "../api/client";

const COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

interface Props {
  findings: Finding[];
}

export default function SeverityChart({ findings }: Props) {
  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const data = Object.entries(counts)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => {
      const order = ["critical", "high", "medium", "low", "info"];
      return order.indexOf(a.name) - order.indexOf(b.name);
    });

  if (data.length === 0) {
    return <p style={{ color: "var(--text-dim)", textAlign: "center" }}>No data</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={50}
          outerRadius={80}
          paddingAngle={3}
          dataKey="value"
          nameKey="name"
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name] || "#6b7280"} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            fontSize: 13,
          }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
