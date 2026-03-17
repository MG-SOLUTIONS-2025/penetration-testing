import { useEffect } from "react";
import { connectScanWS } from "../api/client";
import { useScanStore } from "../stores/scanStore";

interface Props {
  taskId: string;
  scanId: string;
}

export default function ScanProgress({ taskId, scanId }: Props) {
  const progress = useScanStore((s) => s.progress[scanId]);
  const setProgress = useScanStore((s) => s.setProgress);

  useEffect(() => {
    const ws = connectScanWS(taskId);

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setProgress(scanId, { percent: data.percent, message: data.message });
    };

    ws.onerror = () => {
      setProgress(scanId, { percent: -1, message: "WebSocket error" });
    };

    return () => ws.close();
  }, [taskId, scanId, setProgress]);

  if (!progress) return null;

  const percent = Math.max(0, progress.percent);

  return (
    <div style={{ marginTop: 8 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          fontSize: 12,
          color: "var(--text-dim)",
          marginBottom: 4,
        }}
      >
        <span>{progress.message}</span>
        <span>{progress.percent >= 0 ? `${percent}%` : "Error"}</span>
      </div>
      <div className="progress-bar">
        <div
          className="progress-bar-fill"
          style={{
            width: `${percent}%`,
            background: progress.percent < 0 ? "var(--critical)" : undefined,
          }}
        />
      </div>
    </div>
  );
}
