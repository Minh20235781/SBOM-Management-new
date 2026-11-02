import styles from "./ErrorBanner.module.css";

/**
 * Inline error banner. Pass either an {@code error} string/object
 * (auto-extracts the message) or an explicit {@code message}.
 * Renders nothing if both are empty so it's safe to always include
 * at the top of a page.
 */
export default function ErrorBanner({ error, message, title = "Something went wrong", onDismiss }) {
 const resolvedMessage = message ?? extractMessage(error);
 if (!resolvedMessage) return null;

 return (
 <div className={styles.banner} role="alert">
 <svg className={styles.icon} viewBox="0 0 24 24" aria-hidden="true">
 <circle cx="12" cy="12" r="10" />
 <path d="M12 8v4M12 16h.01" />
 </svg>
 <div className={styles.body}>
 <p className={styles.title}>{title}</p>
 <p className={styles.message}>{resolvedMessage}</p>
 </div>
 {onDismiss && (
 <button type="button" className={styles.dismiss} onClick={onDismiss} aria-label="Dismiss">
 ✕
 </button>
 )}
 </div>
 );
}

function extractMessage(err) {
 if (!err) return null;
 if (typeof err === "string") return err;
 if (err.response?.data?.message) return err.response.data.message;
 if (err.message) return err.message;
 return null;
}
