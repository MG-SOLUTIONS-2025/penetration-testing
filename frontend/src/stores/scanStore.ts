import { create } from "zustand";

interface ScanProgress {
  percent: number;
  message: string;
}

interface ScanStore {
  progress: Record<string, ScanProgress>;
  setProgress: (scanId: string, progress: ScanProgress) => void;
  clearProgress: (scanId: string) => void;
}

export const useScanStore = create<ScanStore>((set) => ({
  progress: {},
  setProgress: (scanId, progress) =>
    set((state) => ({
      progress: { ...state.progress, [scanId]: progress },
    })),
  clearProgress: (scanId) =>
    set((state) => {
      const { [scanId]: _, ...rest } = state.progress;
      return { progress: rest };
    }),
}));
