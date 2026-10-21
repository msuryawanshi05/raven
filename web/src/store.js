import { create } from "zustand";

export const api = (p, opt) => fetch("/api" + p, opt).then(r => (r.ok ? r.json() : Promise.reject(r)));

export const useStore = create((set, get) => ({
  sessions: [],
  findings: [],
  activeHunt: null,
  wsMessages: [],
  fetchSessions: async () => set({ sessions: await api("/sessions").catch(() => []) }),
  fetchFindings: async () => set({ findings: await api("/findings").catch(() => []) }),
  startHunt: async (params) => {
    const { session_id } = await api("/hunt", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(params),
    });
    set({ activeHunt: session_id, wsMessages: [] });
    return session_id;
  },
  appendWsMessage: (m) => set({ wsMessages: [...get().wsMessages, m] }),
  clearActiveHunt: () => set({ activeHunt: null, wsMessages: [] }),
}));
