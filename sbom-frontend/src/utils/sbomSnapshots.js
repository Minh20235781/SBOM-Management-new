function withStore(name, mode, operation) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("sbom-reconciliation", 2);
    open.onupgradeneeded = (event) => {
      if (event.oldVersion < 1) {
        open.result.createObjectStore("normalized", { keyPath: "id" });
        open.result.createObjectStore("comparisons", { keyPath: "id" }).createIndex("staticId", "staticId");
      }
      open.result.createObjectStore("originals");
    };
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const transaction = db.transaction(name, mode);
      const request = operation(transaction.objectStore(name));
      transaction.oncomplete = () => { db.close(); resolve(request.result); };
      transaction.onabort = () => { db.close(); reject(transaction.error || request.error); };
    };
  });
}

async function fingerprint(content) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content));
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function getOriginalSbom(hash) {
  return withStore("originals", "readonly", store => store.get(hash));
}

export async function saveNormalizedSbom(sbom, name, original = null) {
  const content = typeof sbom === "string" ? sbom.replace(/^\uFEFF/, "") : JSON.stringify(sbom);
  const document = JSON.parse(content);
  if (!document || (!Array.isArray(document.components) && !Array.isArray(document.packages))) {
    throw new Error("SBOM cần có danh sách thành phần hợp lệ.");
  }
  const id = await fingerprint(content);
  const originalHash = document.metadata?.properties?.find(p => p.name === "devops.provenance.file_sha256")?.value;
  if (original && originalHash) {
    await withStore("originals", "readwrite", store => store.put(original, originalHash));
  }
  const originalAvailable = originalHash && await withStore("originals", "readonly", store => store.getKey(originalHash));
  const record = {
    originalHash: originalAvailable || null,
    id, content, name: name || document.metadata?.component?.name || "SBOM",
    version: document.metadata?.component?.version,
    count: document.components?.length ?? document.packages?.length ?? 0,
    savedAt: new Date().toISOString(),
  };
  await withStore("normalized", "readwrite", (store) => store.put(record));
  return record;
}

export async function listNormalizedSboms() {
  const records = await withStore("normalized", "readonly", (store) => store.getAll());
  return records.sort((a, b) => b.savedAt.localeCompare(a.savedAt));
}

export async function saveSbomComparison(staticId, runtime) {
  const record = {
    ...runtime,
    id: `${staticId}/${runtime.sessionId}`,
    staticId,
    runtimeSha256: await fingerprint(runtime.content),
  };
  await withStore("comparisons", "readwrite", (store) => store.put(record));
  return record;
}

export async function listSbomComparisons(staticId) {
  const records = await withStore("comparisons", "readonly", (store) => store.index("staticId").getAll(staticId));
  return records.sort((a, b) => b.scannedAt.localeCompare(a.scannedAt));
}
