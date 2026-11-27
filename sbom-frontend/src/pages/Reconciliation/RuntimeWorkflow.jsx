import { useEffect, useRef, useState } from "react";
import Button from "../../components/shared/Button";
import { Input } from "../../components/shared/Form";
import { generateRuntimeSbom } from "../../api/reconciliationApi";
import { attachBackend, readBrowserLog } from "./runtimeEvidence";
import styles from "./ReconciliationPage.module.css";

async function runner(action, fields) {
  const res = await fetch("/__sbom_job", {method:"POST", headers:{"Content-Type":"application/json","X-SBOM-Job":"1"},
    body:JSON.stringify({action,...fields}),keepalive:action==="stop"});
  const data = await res.json().catch(()=>({error:"Runner yêu cầu Vite chạy trên localhost."}));
  if (!res.ok || data.error) throw Error(data.error || "Runner không phản hồi.");
  return data;
}

export default function RuntimeWorkflow({ digest, onStart, onResult }) {
  const [command,setCommand]=useState("npm run dev");
  const [url,setUrl]=useState("http://localhost:3000");
  const [job,setJob]=useState(null);
  const [step,setStep]=useState("idle");
  const [error,setError]=useState("");
  const active=useRef(null);
  const mounted=useRef(false);
  useEffect(()=>{
    mounted.current=true;
    const release=()=>{const id=active.current; active.current=null; if(id) runner("stop",{id}).catch(()=>{});};
    window.addEventListener("pagehide",release);
    return ()=>{mounted.current=false;window.removeEventListener("pagehide",release);release();};
  },[]);
  const id=job?.id;
  useEffect(()=>{
    if (!id || job.state!=="running") return;
    let closed=false;
    const timer=setInterval(async()=>{
      try {const next=await runner("status",{id});if(!closed && active.current===id)setJob(next);}
      catch(e){if(!closed)setError(e.message);}
    },1000);
    return ()=>{closed=true;clearInterval(timer);};
  },[id,job?.state]);

  async function start() {
    setError(""); setStep("starting"); setJob(null); onStart();
    try {
      const target=new URL(url);
      if(!["http:","https:"].includes(target.protocol)||!["localhost","127.0.0.1","[::1]"].includes(target.hostname)||target.username||target.password)
        throw Error("Chọn URL localhost của ứng dụng do runner khởi động.");
      const next=await runner("start",{command:command.trim(),digest});
      if(!mounted.current){await runner("stop",{id:next.id});return;}
      active.current=next.id;setJob(next);setStep("ready");
    } catch(e){if(mounted.current){setError(e.message);setStep("idle");}}
  }
  async function stop() {
    try {const next=await runner("stop",{id});active.current=null;setJob(next);setStep("stopped");}
    catch(e){setError(e.message);}
  }
  async function collect() {
    setError("");setStep("browser");
    try {
      const result=await generateRuntimeSbom({targetUrl:url,observedOnly:true});
      if(!result?.success) throw Error(result?.message || "Thu CDP thất bại.");
      let runtime=readBrowserLog(result);
      if(active.current!==id)return;
      setStep("merge");
      const snapshot=await runner("evidence",{id});
      const ids=new Set(runtime.auditLog.capturedNetworkRequests.map(r=>r.backendRequestId).filter(Boolean));
      const matches=snapshot.inventories.filter(i=>i.requests.some(r=>ids.has(r.requestId)));
      if(!matches.length)throw Error("Chưa có request chung. Kiểm tra URL và bảo đảm trang gửi request đến backend đang chạy.");
      for(const inventory of matches) runtime=attachBackend(runtime,inventory,digest);
      const ended=await runner("stop",{id});
      if(active.current!==id)return;
      active.current=null;setJob(ended);setStep("done");onResult(runtime);
    } catch(e){if(active.current===id){setError(e.message);setStep("ready");}}
  }
  const running=job?.state==="running";
  const collecting=step==="browser"||step==="merge";
  const states=[running?"Đang chạy":step==="done"?"Hoàn tất":job?.state==="failed"?"Thất bại":step==="starting"?"Đang mở":job?"Đã dừng":"Chờ",
    collecting?(step==="browser"?"Đang thu":"Hoàn tất"):step==="done"?"Hoàn tất":"Chờ",
    step==="merge"?"Đang ghép":step==="done"?"Hoàn tất":"Chờ"];
  return <section className={styles.workflow}>
    <label>Lệnh backend<Input value={command} disabled={running||step==="starting"} onChange={e=>setCommand(e.target.value)} /></label>
    <details><summary>Cấu hình runner trên máy phát triển</summary>
      <p>Trước khi chạy Vite, đặt SBOM_WORKFLOW_DIR trỏ tới thư mục chứa package.json và SBOM_STATIC_FILE trỏ tới SBOM gốc. Runner hỗ trợ script dev và start của npm hoặc pnpm.</p></details>
    <label>URL ứng dụng<Input type="url" value={url} disabled={collecting} onChange={e=>setUrl(e.target.value)} /></label>
    <div className={styles.actions}>
      <Button disabled={!digest||running||step==="starting"} onClick={start}>Chạy workflow</Button>
      {running && <><Button variant="secondary" disabled={collecting} onClick={collect}>Thu phiên và ghép log</Button>
      <Button variant="ghost" onClick={stop}>Dừng job</Button></>}
    </div>
    <ol className={styles.jobs}>{["Khởi động backend","Thu frontend qua CDP","Ghép bằng chứng"].map((name,i)=><li key={name}><span>{name}</span><strong>{states[i]}</strong></li>)}</ol>
    {job && <pre aria-label="Đầu ra terminal">{job.output || "Đang chờ stdout / stderr…"}</pre>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
