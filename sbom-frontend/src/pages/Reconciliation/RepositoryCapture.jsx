import { useEffect, useRef, useState } from "react";
import Button from "../../components/shared/Button";
import { Input } from "../../components/shared/Form";
import { projectFromUrl } from "../../../../scripts/repo-runtime/url.mjs";
import styles from "./ReconciliationPage.module.css";

async function collect(url, signal, onStep) {
  const response = await fetch("/api/runtime/repository", { method:"POST", signal,
    headers:{ "Content-Type":"application/json", "X-SBOM-Runtime":"1" }, body:JSON.stringify({url}) });
  if (!response.ok) throw Error((await response.json().catch(()=>({}))).error || "Runner chưa sẵn sàng.");
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  let result;
  for (;;) {
    const {value, done} = await reader.read();
    if (done) break;
    buffer += value;
    const lines = buffer.split("\n");
    buffer = lines.pop();
    for (const line of lines) {
      const event = JSON.parse(line);
      if (event.error) throw Error(event.error);
      if (event.step) onStep(event.step);
      if (event.runtime && event.staticContent) result = event;
    }
  }
  if (!result) throw Error("Phiên thu kết thúc trước khi có log runtime.");
  return result;
}

export default function RepositoryCapture({url, onChange, busy, source, onWebsite, onStart, onResult, setBusy}) {
  const repo = projectFromUrl(url);
  const parsed = URL.canParse(url) ? new URL(url) : null;
  const website = parsed && ["http:", "https:"].includes(parsed.protocol) && !parsed.username && !parsed.password && parsed.hostname !== "github.com";
  const [steps,setSteps]=useState([]);
  const [error,setError]=useState("");
  const [running,setRunning]=useState(false);
  const active=useRef(null);
  useEffect(()=>()=>active.current?.abort(),[]);
  async function start(event) {
    event.preventDefault();
    if (busy || active.current) return;
    if (!repo) {
      if (website && source) await onWebsite();
      return;
    }
    const controller=new AbortController();
    active.current=controller;
    onStart();
    setSteps([]); setError(""); setRunning(true); setBusy(true);
    try {
      const result=await collect(url,controller.signal,step=>setSteps(list=>[...list,step]));
      await onResult(result);
      setSteps(list=>[...list,"Đã thu log và chọn SBOM tĩnh của phiên"]);
    } catch(err) { setError(controller.signal.aborted ? "Đã hủy phiên thu." : err.message); }
    finally { active.current=null; setRunning(false); setBusy(false); }
  }
  return <section className={styles.workflow}>
    <form onSubmit={start} className={styles.workflow}>
      <label>Link repo GitHub hoặc website<Input required type="url" placeholder="https://…" disabled={busy} value={url} onChange={e=>{onChange(e.target.value);setError("");setSteps([]);}} /></label>
      <small>{repo ? "Chạy repo trong sandbox và dùng SBOM từ lockfile làm Nguồn 1." : website ? (source ? "Thu phiên trình duyệt trên website." : "Chọn SBOM ở Nguồn 1 để thu phiên website.") : "Dán link repo công khai hoặc địa chỉ website đang chạy."}</small>
      <div className={styles.actions}><Button type="submit" disabled={busy || (!repo && !(website && source))}>Thu runtime</Button>
      {running && <Button variant="secondary" onClick={()=>active.current?.abort()}>Hủy</Button>}</div>
    </form>
    {(steps.length>0 || error) && <div className={styles.actionsPanel} aria-live="polite"><h3>Phiên thu từ repo</h3>
      <ol>{steps.map(step=><li key={step}>{step}</li>)}</ol>{error && <p role="alert">{error}</p>}</div>}
  </section>;
}
