import { useEffect, useState } from "react";

/**
 * Tiny promise-based confirm. Use {@link useConfirm} to get
 * a {@code confirm(message, options)} function that resolves
 * to {@code true} when the user clicks "Confirm" and
 * {@code false} otherwise. Replaces the browser's blocking
 * {@code window.confirm} with a non-blocking modal that
 * matches the rest of the dashboard.
 */
export function useConfirm() {
  const [state, setState] = useState(null);

  const confirm = (message, options = {}) => {
    return new Promise((resolve) => {
      setState({ message, options, resolve });
    });
  };

  const close = (result) => {
    if (state?.resolve) state.resolve(result);
    setState(null);
  };

  const node = state ? (
    <ConfirmDialog
      message={state.message}
      options={state.options}
      onClose={close}
    />
  ) : null;

  return { confirm, node };
}

export default function ConfirmDialog({ message, options = {}, onClose }) {
  const {
    title = "Are you sure?",
    confirmText = "Confirm",
    cancelText = "Cancel",
    tone = "danger", // "danger" | "primary"
    busy = false,
  } = options;

  // Close on ESC.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape" && !busy) onClose(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onClose]);

  const confirmColor = tone === "primary" ? "var(--color-primary)" : "var(--color-danger, #b91c1c)";

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 1100,
        background: "rgba(15, 23, 42, 0.45)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && !busy) onClose(false);
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        style={{
          background: "var(--bg-surface)",
          borderRadius: "var(--radius-lg)",
          boxShadow: "var(--shadow-lg)",
          padding: "var(--space-5)",
          maxWidth: 480, width: "calc(100% - 32px)",
          border: "1px solid var(--border-default)",
        }}
      >
        <h3 style={{ margin: 0, fontSize: "var(--text-md)", color: "var(--text-primary)" }}>
          {title}
        </h3>
        <div
          style={{
            marginTop: "var(--space-3)",
            color: "var(--text-secondary)",
            fontSize: "var(--text-sm)",
            whiteSpace: "pre-wrap",
          }}
        >
          {message}
        </div>
        <div
          style={{
            display: "flex", justifyContent: "flex-end", gap: "var(--space-2)",
            marginTop: "var(--space-4)",
          }}
        >
          <button
            type="button"
            disabled={busy}
            onClick={() => onClose(false)}
            style={{
              background: "transparent",
              border: "1px solid var(--border-default)",
              borderRadius: "var(--radius-md)",
              padding: "8px 14px",
              fontSize: "var(--text-sm)",
              color: "var(--text-secondary)",
              cursor: busy ? "not-allowed" : "pointer",
            }}
          >
            {cancelText}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => onClose(true)}
            style={{
              background: confirmColor,
              border: "none",
              borderRadius: "var(--radius-md)",
              padding: "8px 14px",
              fontSize: "var(--text-sm)",
              fontWeight: 600,
              color: "white",
              cursor: busy ? "not-allowed" : "pointer",
            }}
          >
            {busy ? "Working…" : confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
