import { useEffect, useState } from "react";
import Button from "../../components/shared/Button";
import { Input } from "../../components/shared/Form";
import { dispatch, github } from "./githubActions";
import { projectFromUrl } from "../../../../scripts/repo-runtime/url.mjs";
import styles from "./ReconciliationPage.module.css";

const labels = { queued: "Đang chờ", in_progress: "Đang chạy", success: "Thành công", failure: "Thất bại",
  cancelled: "Đã hủy", skipped: "Bỏ qua", timed_out: "Hết thời gian", waiting: "Chờ phê duyệt" };
const status = item => labels[item.conclusion || item.status] || item.conclusion || item.status;

function JobLogs({ run, job }) {
  const [output, setOutput] = useState("");
  const [loading, setLoading] = useState(false);
  async function load() {
    setLoading(true);
    try {
      const response = await fetch(`https://api.github.com/repos/${run.repo}/actions/jobs/${job.id}/logs`, {
        headers: { Authorization: "Bearer " + run.token }
      });
      if (!response.ok) throw Error("GitHub " + response.status);
      const lines = (await response.text()).trimEnd().split(/\r?\n/);
      setOutput(lines.slice(-500).join("\n") || "Job chưa có log.");
    } catch {
      setOutput("Chưa đọc được log qua trình duyệt. Mở job trên GitHub để xem toàn bộ log.");
    } finally { setLoading(false); }
  }
  return <><div className={styles.actions}>
    {job.status === "completed" && <Button size="sm" variant="secondary" disabled={loading} onClick={load}>
      {loading ? "Đang tải…" : "Xem 500 dòng log cuối"}</Button>}
    <a href={job.html_url} target="_blank" rel="noreferrer">Mở job trên GitHub ↗</a>
  </div>{output && <pre>{output}</pre>}</>;
}

function RunPanel({ run }) {
  const [view, setView] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    let timer;
    async function refresh() {
      const read = endpoint => github(run.repo, "/actions/runs/" + run.id + endpoint, run.token, { signal: controller.signal });
      try {
        const [summary, data] = await Promise.all([read(""), read("/jobs?per_page=100")]);
        if (controller.signal.aborted) return;
        setView({ summary, jobs: data.jobs });
        setError("");
        if (summary.status === "completed") return;
      } catch (err) {
        if (controller.signal.aborted) return;
        setError(err.message);
      }
      timer = setTimeout(refresh, 6000);
    }
    refresh();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [run]);
  return <section className={styles.actionsPanel}>
    <header><div><small>GitHub Actions · {run.repo}</small><h3>{view?.summary.name || "Workflow runtime"} #{view?.summary.run_number || run.id}</h3></div>
      <a href={run.url} target="_blank" rel="noreferrer">Mở lượt chạy ↗</a></header>
    <p role="status">{view ? status(view.summary) : "Đang lấy trạng thái từ GitHub…"}</p>
    {view?.jobs.map(job => <details key={job.id} open>
      <summary>{job.name} · {status(job)}</summary>
      <ol>{job.steps?.map(step => <li key={step.number}><span>{step.name}</span><strong>{status(step)}</strong></li>)}</ol>
      <JobLogs run={run} job={job} />
    </details>)}
    {error && <p role="alert">{error}</p>}
    {view?.summary.conclusion === "success" && <p>Tải artifact trong lượt chạy, giải nén rồi chọn runtime-log.json ở ô tải log phía trên.</p>}
  </section>;
}

export default function RuntimeWorkflow({ url, onStart }) {
  const [workflow, setWorkflow] = useState("runtime-sbom.yml");
  const [token, setToken] = useState("");
  const [run, setRun] = useState(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const repo = projectFromUrl(url)?.repo;
  async function start(event) {
    event.preventDefault();
    if (!repo || starting) return;
    setStarting(true); setError("");
    try {
      const next = await dispatch(repo, workflow.trim(), token.trim());
      onStart();
      setRun(next);
    } catch (err) { setError(err.message); }
    finally { setStarting(false); }
  }
  return <section className={styles.workflow}>
    <form onSubmit={start} className={styles.workflow}>
      <small>{repo || "Dán link repo GitHub vào ô phía trên để chạy workflow."}</small>
      <label>Workflow thu runtime trên nhánh mặc định<Input required value={workflow} pattern="[\w.\-]+\.ya?ml" onChange={e => setWorkflow(e.target.value)} /></label>
      <details><summary>Thiết lập workflow cho repo</summary><p>Tải <a href={import.meta.env.BASE_URL + "runtime-sbom.yml"} download>workflow mẫu</a>, chỉnh thư mục ứng dụng, lệnh khởi động, URL và đường dẫn SBOM gốc. Lưu vào .github/workflows/runtime-sbom.yml trên nhánh mặc định. Để chạy ví dụ trong repo công cụ, nhập runtime-demo.yml.</p></details>
      <label>GitHub token của phiên<Input type="password" autoComplete="off" required value={token} onChange={e => setToken(e.target.value)} /></label>
      <small>Dùng fine-grained token có quyền Actions: Read and write trên repo đã chọn. Token được gửi trực tiếp tới GitHub.</small>
      <Button type="submit" disabled={!repo || !workflow.trim() || !token.trim() || starting}>{starting ? "Đang gửi đến GitHub…" : "Chạy workflow"}</Button>
    </form>
    {error && <p role="alert">{error}</p>}
    {run && <RunPanel key={run.repo + run.id} run={run} />}
  </section>;
}
