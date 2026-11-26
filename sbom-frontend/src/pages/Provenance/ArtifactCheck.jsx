import { useState } from "react";

import { verifyArtifact } from "./verifyArtifact";

export default function ArtifactCheck({ component }) {
  const [record, setRecord] = useState(null);
  const [busy, setBusy] = useState(false);
  async function verify(event) {
    const file = event.target.files[0];
    setRecord(null);
    if (!file) return;
    setBusy(true);
    try {
      setRecord(await verifyArtifact(file, component));
    } catch (err) { setRecord({ error: err.message }); }
    finally { setBusy(false); }
  }
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(record, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "artifact-checksum.json";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <div>
    <p>Tệp phát hành tham chiếu · {component.artifactUrl || component.officialRegistry}</p>
    <label>Chọn đúng tarball hoặc JAR để so byte với checksum {component.officialHashAlgorithm}
      <input type="file" onChange={verify} disabled={busy} />
    </label>
    {record && <p role="status">{record.error || record.status} {record.sha256 && <>· SHA-256 {record.sha256} <button onClick={download}>Xuất bằng chứng</button></>}</p>}
  </div>;
}
