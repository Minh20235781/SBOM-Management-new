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

export default function RepositoryCapture({onStart, onResult, setBusy}) {
  const [url,setUrl]=useState("");
  const [steps,setSteps]=useState([]);
  const [error,setError]=useState("");
  const [running,setRunning]=useState(false);
  const active=useRef(null);
  useEffect(()=>()=>active.current?.abort(),[]);
  async function start(event) {
    event.preventDefault();
    if (!projectFromUrl(url) || active.current) return;
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
      <label>Repo GitHub công khai<Input required type="url" placeholder="https://github.com/owner/project" disabled={running} value={url} onChange={e=>setUrl(e.target.value)} /></label>
      <small>Chọn repo hoặc thư mục ứng dụng có package-lock.json và script dev/start. Phiên thành công sẽ dùng SBOM từ lockfile làm Nguồn 1 và log quan sát tại đường dẫn / làm Nguồn 2.</small>
      <div className={styles.actions}><Button type="submit" disabled={!projectFromUrl(url) || running}>Thu runtime từ repo</Button>
      {running && <Button variant="secondary" onClick={()=>active.current?.abort()}>Hủy</Button>}</div>
    </form>
    {(steps.length>0 || error) && <div className={styles.actionsPanel} aria-live="polite"><h3>Phiên thu từ repo</h3>
      <ol>{steps.map(step=><li key={step}>{step}</li>)}</ol>{error && <p role="alert">{error}</p>}</div>}
  </section>;
}
