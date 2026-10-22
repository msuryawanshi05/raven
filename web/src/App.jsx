import React, { useEffect, useRef, useState } from "react";
import { Routes, Route, Link, useParams, useNavigate } from "react-router-dom";
import { ReactFlow, Background, Controls } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import ReactMarkdown from "react-markdown";
import { api, useStore } from "./store.js";

const SEV = { CRITICAL: "#dc2626", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#3b82f6" };
const NODE_COLOR = { domain: "#ef4444", subdomain: "#3b82f6", endpoint: "#22c55e",
  vuln: "#f59e0b", payload: "#a855f7", service: "#6b7280", port: "#6b7280", technology: "#6b7280" };
const NATIVE_TOOLS = ["subdomain_enum", "probe_http", "check_headers", "check_info_disclosure",
  "check_subdomain_takeover", "check_cors", "js_analysis", "tech_fingerprint", "port_scan",
  "check_xss", "check_sqli", "check_ssrf", "check_open_redirect", "check_idor", "check_ssti"];
const ToolStatus = () => (
  <div className="bg-gray-900 rounded p-4 mb-6">
    <div className="text-sm font-bold mb-2">Native engine ready - pure Python, no external tools required</div>
    <div className="grid grid-cols-3 md:grid-cols-5 gap-1 text-xs">
      {NATIVE_TOOLS.map((t) => <div key={t} className="text-gray-300"><span className="text-green-500">OK</span> {t}</div>)}
    </div>
  </div>);
const Badge = ({ t }) => (
  <span style={{ background: SEV[(t || "").toUpperCase()] || "#6b7280" }}
        className="px-2 py-0.5 rounded text-xs text-white">{t}</span>);

function Nav() {
  return (
    <div className="flex gap-4 px-6 py-3 border-b border-gray-800 text-sm">
      <span className="font-bold text-red-500 mr-4">RAVEN</span>
      <Link to="/" className="text-gray-400 hover:text-white">Dashboard</Link>
      <Link to="/sessions" className="text-gray-400 hover:text-white">Sessions</Link>
      <Link to="/findings" className="text-gray-400 hover:text-white">Findings</Link>
      <Link to="/graph" className="text-gray-400 hover:text-white">Graph</Link>
    </div>);
}

function Launcher({ onClose }) {
  const nav = useNavigate();
  const startHunt = useStore((s) => s.startHunt);
  const [f, setF] = useState({ target: "", mode: "auto", platform: "", ai_mode: false, owasp_only: false });
  const submit = async () => {
    try { const id = await startHunt(f); onClose(); nav("/hunt/" + id); }
    catch { alert("hunt failed to start"); }
  };
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center" onClick={onClose}>
      <div className="bg-gray-900 p-6 rounded-lg w-96" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-lg font-bold mb-3">Start new hunt</h2>
        <input className="w-full bg-gray-800 rounded px-2 py-1 mb-2" placeholder="target"
               value={f.target} onChange={(e) => setF({ ...f, target: e.target.value })} />
        <select className="w-full bg-gray-800 rounded px-2 py-1 mb-2" value={f.mode}
                onChange={(e) => setF({ ...f, mode: e.target.value })}>
          <option value="auto">auto</option><option value="ask">ask</option></select>
        <select className="w-full bg-gray-800 rounded px-2 py-1 mb-2" value={f.platform}
                onChange={(e) => setF({ ...f, platform: e.target.value })}>
          <option value="">none</option><option value="hackerone">HackerOne</option>
          <option value="bugcrowd">Bugcrowd</option><option value="huntr">Huntr</option></select>
        <label className="flex gap-2 text-sm mb-1"><input type="checkbox" checked={f.ai_mode}
          onChange={(e) => setF({ ...f, ai_mode: e.target.checked })} />AI mode</label>
        <label className="flex gap-2 text-sm mb-4"><input type="checkbox" checked={f.owasp_only}
          onChange={(e) => setF({ ...f, owasp_only: e.target.checked })} />OWASP only</label>
        <div className="flex gap-2 justify-end">
          <button className="px-3 py-1 rounded bg-gray-700" onClick={onClose}>Cancel</button>
          <button className="px-3 py-1 rounded bg-red-600" onClick={submit}>Launch</button></div>
      </div></div>);
}

function Dashboard() {
  const { sessions, findings, fetchSessions, fetchFindings } = useStore();
  const [modal, setModal] = useState(false);
  useEffect(() => { fetchSessions(); fetchFindings(); }, []);
  const high = findings.filter((x) => ["HIGH", "CRITICAL"].includes((x.severity || "").toUpperCase())).length;
  const Stat = ({ n, l }) => (<div className="bg-gray-900 rounded p-4">
    <div className="text-2xl font-bold">{n}</div><div className="text-xs text-gray-400">{l}</div></div>);
  return (
    <div className="p-6">
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Stat n={sessions.length} l="Sessions" /><Stat n={findings.length} l="Findings" />
        <Stat n={high} l="High / Critical" /><Stat n={sessions[0]?.target || "-"} l="Last hunt" /></div>
      <ToolStatus />
      <button className="px-4 py-2 rounded bg-red-600 mb-4" onClick={() => setModal(true)}>Start new hunt</button>
      <table className="w-full text-sm"><thead className="text-gray-400 text-left">
        <tr><th>Target</th><th>Started</th><th>Findings</th><th>Status</th><th></th></tr></thead>
        <tbody>{sessions.map((s) => (<tr key={s.id} className="border-t border-gray-800">
          <td className="py-2">{s.target}</td><td>{s.started_at}</td><td>{s.finding_count}</td>
          <td>{s.status}</td><td><Link className="text-blue-400" to={"/hunt/" + s.id}>View</Link></td></tr>))}</tbody></table>
      {modal && <Launcher onClose={() => setModal(false)} />}
    </div>);
}

function Hunt() {
  const { id } = useParams();
  const [log, setLog] = useState([]);
  const [finds, setFinds] = useState([]);
  const [done, setDone] = useState(false);
  const box = useRef();
  useEffect(() => {
    const ws = new WebSocket("ws://" + location.host + "/ws/hunt/" + id);
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.type === "finding") setFinds((f) => [...f, m.content]);
      else if (m.type === "done" || m.type === "error") setDone(true);
      else setLog((l) => [...l, m]);
    };
    return () => ws.close();
  }, [id]);
  useEffect(() => { if (box.current) box.current.scrollTop = box.current.scrollHeight; }, [log]);
  const COLOR = { thought: "text-cyan-400", action: "text-fuchsia-400", observation: "text-blue-300", error: "text-red-400" };
  const stop = () => api("/hunt/" + id, { method: "DELETE" }).catch(() => {});
  return (
    <div className="p-6">
      <div className="flex justify-between mb-3">
        <div><h2 className="font-bold">Hunt {id}</h2>
          {!done && (() => { const last = [...log].reverse().find((m) => m.type === "action");
            return <div className="text-xs text-fuchsia-400">{last ? "running: " + (last.content || "").split(" ")[0] : "starting..."}</div>; })()}</div>
        {!done ? <button className="px-3 py-1 rounded bg-red-600" onClick={stop}>Stop hunt</button>
               : <div className="flex gap-2"><Link className="px-3 py-1 rounded bg-gray-700" to={"/reports/" + id}>View report</Link>
                     <Link className="px-3 py-1 rounded bg-gray-700" to="/graph">View graph</Link></div>}</div>
      <div className="grid grid-cols-2 gap-4">
        <div ref={box} className="bg-black rounded p-3 h-96 overflow-auto font-mono text-xs">
          {log.map((m, i) => <div key={i} className={COLOR[m.type] || "text-gray-300"}>
            <span className="text-gray-600">{(m.type || "").toUpperCase()} </span>
            {typeof m.content === "string" ? m.content : JSON.stringify(m.content)}</div>)}</div>
        <div className="bg-gray-900 rounded p-3 h-96 overflow-auto"><div className="text-gray-400 text-sm mb-2">Findings</div>
          {finds.map((f, i) => <div key={i} className="mb-2 text-sm"><Badge t={f.severity} /> <b>{f.vuln}</b> <span className="text-gray-400">{f.target}</span></div>)}</div>
      </div></div>);
}

function Sessions() {
  const { sessions, fetchSessions } = useStore();
  const nav = useNavigate();
  useEffect(() => { fetchSessions(); }, []);
  return (<div className="p-6"><h2 className="font-bold mb-3">Sessions</h2>
    <table className="w-full text-sm"><thead className="text-gray-400 text-left">
      <tr><th>Target</th><th>Started</th><th>Findings</th><th>Status</th></tr></thead>
      <tbody>{sessions.map((s) => <tr key={s.id} className="border-t border-gray-800 cursor-pointer hover:bg-gray-900"
        onClick={() => nav("/hunt/" + s.id)}><td className="py-2">{s.target}</td><td>{s.started_at}</td>
        <td>{s.finding_count}</td><td>{s.status}</td></tr>)}</tbody></table></div>);
}

function Findings() {
  const { findings, fetchFindings } = useStore();
  const [sev, setSev] = useState("ALL");
  const [open, setOpen] = useState(null);
  useEffect(() => { fetchFindings(); }, []);
  const shown = findings.filter((r) => sev === "ALL" || (r.severity || "").toUpperCase() === sev);
  return (<div className="p-6"><div className="flex gap-4 items-center mb-3"><h2 className="font-bold">Findings</h2>
    <select className="bg-gray-800 rounded px-2 py-1 text-sm" value={sev} onChange={(e) => setSev(e.target.value)}>
      {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => <option key={s}>{s}</option>)}</select></div>
    <table className="w-full text-sm"><thead className="text-gray-400 text-left">
      <tr><th>Target</th><th>Vuln</th><th>Severity</th><th>Session</th><th>At</th></tr></thead>
      <tbody>{shown.map((r, i) => <React.Fragment key={i}>
        <tr className="border-t border-gray-800 cursor-pointer" onClick={() => setOpen(open === i ? null : i)}>
          <td className="py-2">{r.target}</td><td>{r.vuln}</td><td><Badge t={r.severity} /></td>
          <td className="text-gray-400">{r.session}</td><td>{r.discovered_at}</td></tr>
        {open === i && <tr className="bg-gray-900"><td colSpan="5" className="p-3 text-xs font-mono">command: {r.command || "-"}</td></tr>}
      </React.Fragment>)}</tbody></table></div>);
}

function Graph() {
  const [data, setData] = useState({ nodes: [], links: [] });
  useEffect(() => { api("/graph").then(setData).catch(() => {}); }, []);
  const nodes = (data.nodes || []).map((n, i) => ({
    id: String(n.id), position: { x: 180 * (i % 5), y: 110 * Math.floor(i / 5) },
    data: { label: n.id }, style: { background: NODE_COLOR[n.type] || "#6b7280", color: "#fff", fontSize: 10 } }));
  const edges = (data.links || []).map((l, i) => ({ id: "e" + i, source: String(l.source), target: String(l.target) }));
  return (<div className="p-6"><h2 className="font-bold mb-3">Hunt graph</h2>
    <div style={{ height: 520 }} className="bg-gray-900 rounded">
      <ReactFlow nodes={nodes} edges={edges} fitView><Background /><Controls /></ReactFlow></div></div>);
}

function Report() {
  const { id } = useParams();
  const [md, setMd] = useState("");
  useEffect(() => { api("/reports/" + id).then((d) => setMd(d.markdown)).catch(() => setMd("report unavailable")); }, [id]);
  const download = () => { const b = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = id + "_report.md"; a.click(); };
  return (<div className="p-6"><div className="flex justify-between mb-3"><h2 className="font-bold">Report {id}</h2>
    <button className="px-3 py-1 rounded bg-gray-700" onClick={download}>Download .md</button></div>
    <div className="bg-gray-900 rounded p-4 text-sm"><ReactMarkdown>{md}</ReactMarkdown></div></div>);
}

export default function App() {
  return (<div><Nav /><Routes>
    <Route path="/" element={<Dashboard />} />
    <Route path="/hunt/:id" element={<Hunt />} />
    <Route path="/sessions" element={<Sessions />} />
    <Route path="/findings" element={<Findings />} />
    <Route path="/graph" element={<Graph />} />
    <Route path="/reports/:id" element={<Report />} />
  </Routes></div>);
}
