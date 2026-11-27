export function repositoryPath(value) {
  const match = /^https:\/\/github\.com\/([\w-]+)\/([\w.-]+)\/?$/i.exec(value.trim());
  if (!match) return "";
  const name = match[2].replace(/\.git$/i, "");
  return name && !/^\.+$/.test(name) ? match[1] + "/" + name : "";
}

export async function github(repo, endpoint, token, options = {}) {
  const response = await fetch("https://api.github.com/repos/" + repo + endpoint, {
    ...options, redirect: "error", headers: {
      Accept: "application/vnd.github+json", Authorization: "Bearer " + token,
      "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"
    }
  });
  const data = await response.json().catch(() => ({}));
  if (response.status === 403 && data.message?.includes("personal access token")) {
    throw Error("GitHub từ chối quyền của token trên repo này. Để thử dự án công khai, chọn Repo công khai rồi dán link. Với CI có sẵn, kiểm tra repo và quyền Actions của token.");
  }
  if (!response.ok) throw Error("GitHub " + response.status + " · " + (data.message || response.statusText));
  return data;
}

export async function dispatch(repo, workflow, token) {
  const project = await github(repo, "", token);
  const data = await github(repo, "/actions/workflows/" + encodeURIComponent(workflow) + "/dispatches", token, {
    method: "POST", body: JSON.stringify({ ref: project.default_branch, return_run_details: true })
  });
  if (!Number.isSafeInteger(data.workflow_run_id)) throw Error("GitHub đã nhận lệnh nhưng chưa trả mã lượt chạy. Kiểm tra mục Actions của repo trước khi chạy lại.");
  return { repo, id: data.workflow_run_id, url: data.html_url, token };
}
