import { useEffect, useState } from "react";
import projectApi from "../../../api/projectApi";
import projectDetailApi from "../../../api/projectDetailApi";
import { toast } from "../../shared/Toaster";
import Button from "../../shared/Button";
import ErrorBanner from "../../shared/ErrorBanner";
import Spinner from "../../shared/Spinner";
import styles from "./RecentCommits.module.css";

/**
 * Renders the N most recent upstream commits for a project,
 * with a per-commit file tree (added/modified/deleted files
 * and +/- line counts). Each commit is decorated by the
 * backend with a {@code state} describing whether the
 * project's latest risk snapshot has factored it in yet,
 * and whether the most recent scan that did cover it
 * produced any NEW / FIXED / REOPENED vuln diff rows:
 * <ul>
 *   <li>{@code new} — landed after the latest scan. Shown
 *       with a blue "New" badge and a "Re-scan" button.</li>
 *   <li>{@code scanned-with-impact} — the latest scan that
 *       covered this commit produced diff rows. Shown with
 *       a green "Scanned" badge (and the impact summary
 *       on hover).</li>
 *   <li>{@code no-impact} — the latest scan that covered
 *       this commit changed nothing in the vuln diff (e.g.
 *       CI workflow bumps, source refactors). Shown with a
 *       grey "No impact" badge and no Re-scan button.</li>
 * </ul>
 *
 * Clicking the SHA button expands the per-commit file tree.
 */
export default function RecentCommits({ project, defaultLimit = 5, moduleId = null, onRescanned, onPendingCountChange }) {
  const [commits, setCommits] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [limit, setLimit] = useState(defaultLimit);
  const [expandedSha, setExpandedSha] = useState(null);
  const [rescanningSha, setRescanningSha] = useState(null);

  const load = async (n, forceRefresh = false) => {
    setLoading(true);
    setError(null);
    try {
      const res = await projectApi.commits(project.id, n, forceRefresh);
      // Backend may return either the legacy CommitInfo[]
      // (flat, no state) or the new CommitWithState[] (each
      // entry has a nested .commit + state + impactSummary).
      // Normalise to a flat { commit, state, impactSummary }
      // shape so the rest of this component doesn't need to
      // branch on it.
      const items = Array.isArray(res) ? res : [];
      const flat = items.map((entry) => {
        if (entry && entry.commit) {
          return {
            commit: entry.commit,
            state: entry.state || "new",
            impactSummary: entry.impactSummary || null,
            likelyNoImpact: Boolean(entry.likelyNoImpact),
          };
        }
        // Legacy / unknown shape — fall back to "new" so the
        // user still sees the badge (better than hiding it).
        return { commit: entry, state: "new", impactSummary: null, likelyNoImpact: false };
      });
      setCommits(flat);
      // Notify the parent tab (e.g. OverviewTab) about the
      // count of commits that genuinely need a re-scan. We
      // only count `state === "new"` (not "no-impact") so
      // CI/source commits don't inflate the metric.
      if (typeof onPendingCountChange === "function") {
        const pending = flat.filter((e) => e.state === "new").length;
        onPendingCountChange(pending);
      }
    } catch (e) {
      setError(e?.response?.data?.message || e?.message || "Failed to load commits");
      setCommits([]);
      if (typeof onPendingCountChange === "function") onPendingCountChange(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load(limit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [project.id, limit]);

  const toggle = (sha) => setExpandedSha((prev) => (prev === sha ? null : sha));

  const handleRescan = async (entry) => {
    if (!moduleId) {
      toast.error("No module linked to this project — cannot trigger a re-scan.");
      return;
    }
    const c = entry.commit;
    setRescanningSha(c.sha);
    const loadingToast = toast.loading(`Re-scanning ${c.shortSha || c.sha?.slice(0, 7)}…`, { duration: Infinity });
    try {
      // scanModuleFs doesn't require a RepoConfig — it reads
      // the upstream URL from the project description. This
      // is the path the user has working today, so we use it
      // by default. If the caller wired up scanModuleRepo
      // instead, pass it through moduleId+repoConfig wiring.
      await projectDetailApi.scanModuleFs(project.id, moduleId);
      toast.dismiss(loadingToast);
      toast.success(`Re-scan complete for ${c.shortSha || c.sha?.slice(0, 7)}.`);
      // Refresh the commits so the badges reflect the new
      // scan outcome (was "new", should now be "no-impact"
      // or "scanned-with-impact").
      await load(limit, true);
      onRescanned?.();
    } catch (e) {
      toast.dismiss(loadingToast);
      toast.error(e?.response?.data?.message || e?.message || "Re-scan failed");
    } finally {
      setRescanningSha(null);
    }
  };

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <div>
          <h3 className={styles.title}>Recent upstream commits</h3>
          <p className={styles.subtle}>
            Last {limit} commits on the repo's default branch. <b>New</b> = not yet
            scanned; <b>Scanned</b> = covered by the latest scan and it changed
            something; <b>No impact</b> = scanned, but nothing changed (CI bumps,
            refactors).
          </p>
        </div>
        <div className={styles.actions}>
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className={styles.limitSelect}
          >
            <option value={3}>3</option>
            <option value={5}>5</option>
            <option value={10}>10</option>
          </select>
          <Button size="sm" variant="secondary" onClick={() => load(limit, true)} disabled={loading}>
            {loading ? "Refreshing…" : "Refresh"}
          </Button>
        </div>
      </div>

      {error && <ErrorBanner error={error} />}

      {loading && commits.length === 0 ? (
        <Spinner size="sm" label="Fetching commits from GitHub…" />
      ) : commits.length === 0 ? (
        <p className={styles.subtle} style={{ margin: "var(--space-3) 0 0 0" }}>
          No upstream commits available. The project description may not reference a public
          GitHub repo, or the GitHub API is unreachable.
        </p>
      ) : (
        <ul className={styles.list}>
          {commits.map((entry) => {
            const c = entry.commit;
            const state = entry.state;
            const expanded = expandedSha === c.sha;
            const tree = Array.isArray(c.tree) ? c.tree : [];
            return (
              <li key={c.sha} className={styles.item}>
                <div className={styles.itemHeader}>
                  <button
                    type="button"
                    className={styles.shaBtn}
                    onClick={() => toggle(c.sha)}
                    title={c.sha}
                  >
                    {c.shortSha || c.sha?.slice(0, 7)}
                  </button>
                  <div className={styles.message}>
                    <a
                      href={c.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={styles.messageLink}
                    >
                      {c.message || "(no message)"}
                    </a>
                  </div>
                  <div className={styles.meta}>
                    {state === "new" && <span className={styles.badgeNew}>New</span>}
                    {state === "no-impact" && (
                      <span
                        className={styles.badgeNoImpact}
                        title={
                          entry.likelyNoImpact
                            ? "File diff has no dependency manifest — re-scan unlikely to change vulns"
                            : entry.impactSummary || "Re-scan produced no NEW/FIXED/REOPENED rows"
                        }
                      >
                        No impact
                      </span>
                    )}
                    {state === "scanned-with-impact" && (
                      <span
                        className={styles.badgeScanned}
                        title={entry.impactSummary || "Latest scan produced changes"}
                      >
                        Scanned
                      </span>
                    )}
                    {c.totalChanges > 0 && (
                      <span className={styles.diff}>
                        <span className={styles.add}>+{c.additions}</span>
                        {" "}
                        <span className={styles.del}>−{c.deletions}</span>
                      </span>
                    )}
                    <span className={styles.date}>
                      {c.date ? new Date(c.date).toLocaleDateString() : ""}
                    </span>
                  </div>
                </div>
                <div className={styles.subtle}>
                  {c.author || "unknown"} · click SHA to {expanded ? "collapse" : "expand"} the file tree
                </div>
                {state === "new" && moduleId && (
                  <div className={styles.actions}>
                    <Button
                      size="sm"
                      variant="primary"
                      onClick={() => handleRescan(entry)}
                      disabled={rescanningSha === c.sha}
                    >
                      {rescanningSha === c.sha ? "Re-scanning…" : "Re-scan"}
                    </Button>
                  </div>
                )}
                {state === "new" && !moduleId && (
                  <div className={styles.subtle} style={{ marginTop: 4 }}>
                    Add a Module to enable re-scan from here.
                  </div>
                )}
                {state === "no-impact" && entry.likelyNoImpact && (
                  <div className={styles.subtle} style={{ marginTop: 4 }}>
                    Only CI / source / docs files changed — no dependency manifest to update.
                  </div>
                )}
                {expanded && tree.length > 0 && (
                  <div className={styles.tree}>
                    {tree.slice(0, 20).map((f) => (
                      <div key={f.filename} className={styles.treeRow}>
                        <span className={`${styles.treeStatus} ${styles[`status_${statusClass(f.status)}`] || ""}`}>
                          {statusIcon(f.status)}
                        </span>
                        <code className={styles.treeFile}>{f.filename}</code>
                        <span className={styles.treeDiff}>
                          {f.additions > 0 && <span className={styles.add}>+{f.additions}</span>}
                          {f.deletions > 0 && <span className={styles.del}>−{f.deletions}</span>}
                        </span>
                      </div>
                    ))}
                    {tree.length > 20 && (
                      <div className={styles.subtle} style={{ padding: "4px 8px" }}>
                        … and {tree.length - 20} more file(s)
                      </div>
                    )}
                  </div>
                )}
                {expanded && tree.length === 0 && (
                  <div className={styles.subtle} style={{ padding: "8px 12px" }}>
                    No file changes reported (root commit, merge, or binary-only).
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function statusClass(status) {
  const s = (status || "").toLowerCase();
  if (s === "added") return "added";
  if (s === "removed") return "removed";
  if (s === "renamed") return "renamed";
  return "modified";
}

function statusIcon(status) {
  const s = (status || "").toLowerCase();
  if (s === "added") return "+";
  if (s === "removed") return "−";
  if (s === "renamed") return "→";
  return "•";
}
