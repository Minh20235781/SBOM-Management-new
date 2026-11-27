import { useEffect, useState } from "react";
import styles from "./ReconciliationPage.module.css";

function lines(log) {
  const modules = log.packages.map(p => [p.firstLoadedAt, `MODULE  ${p.name}@${p.version}  ${p.method}  ${p.file}`]);
  const requests = log.requests.map(r => [r.startedAt, `HTTP    ${r.method} ${r.path}  ${r.requestId}`]);
  return [...modules, ...requests].sort(([a], [b]) => a.localeCompare(b))
    .map(([time, message]) => `${time}  ${message}`).join("\n");
}

export default function RuntimeTerminal({ inventories, onAttach, extra }) {
  const [handle, setHandle] = useState(null);
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!handle) return;
    let active = true;
    let timer;
    let last;
    async function read() {
      try {
        const file = await handle.getFile();
        if (file.lastModified !== last) {
          const log = JSON.parse(await file.text());
          if (log.format !== "sbom-backend/1" || !Array.isArray(log.packages) || !Array.isArray(log.requests))
            throw new Error("Cần chọn file backend-*.json do agent xuất.");
          if (active) { setPreview(log); setError(""); }
          last = file.lastModified;
        }
      } catch (err) { if (active) { setError(err.message); setPreview(null); last = undefined; } }
      if (active) timer = setTimeout(read, 1500);
    }
    read();
    return () => { active = false; clearTimeout(timer); };
  }, [handle]);

  async function watch() {
    try {
      const [file] = await window.showOpenFilePicker({ types: [{ description: "Log backend", accept: { "application/json": [".json"] } }] });
      setPreview(null);
      setHandle(file);
    } catch (err) { if (err.name !== "AbortError") setError(err.message); }
  }
  const attached = Object.values(inventories || {});
  return <section className={styles.terminal}>
    <h3>Terminal backend</h3>
    {extra}
    {window.showOpenFilePicker && <button type="button" onClick={watch}>Theo dõi file log đang ghi</button>}
    {handle && <button type="button" onClick={() => setHandle(null)}>Dừng theo dõi</button>}
    {error && <p role="alert">{error}</p>}
    {preview && <><p>{handle ? "Đang theo dõi" : "Đã dừng"} · PID {preview.pid} · {preview.packages.length} gói</p>
      <pre>{lines(preview)}</pre>
      <button disabled={!onAttach} onClick={() => onAttach(preview)}>Ghép bản ghi này vào phiên</button></>}
    {!attached.length && <p>Chưa ghép backend. Có thể đối sánh ngay dữ liệu trình duyệt hoặc nhập log backend cùng phiên.</p>}
    {attached.map(log => <details key={log.processId} open><summary>Đã ghép · PID {log.pid} · {log.packages.length} gói</summary>
      <pre>{lines(log)}</pre></details>)}
  </section>;
}
