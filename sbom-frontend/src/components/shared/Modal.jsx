import { useEffect } from "react";
import styles from "./Modal.module.css";

/**
 * Generic modal with backdrop, header, scrollable body and footer.
 * Closes on backdrop click or Escape. The body and footer are
 * passed as children — typically you'll put a <form> in the body
 * and action buttons in the footer.
 */
export default function Modal({
 title,
 size = "md", // "md" | "lg" | "xl"
 onClose,
 children,
 footer,
}) {
 // Close on Escape
 useEffect(() => {
 const onKey = (e) => {
 if (e.key === "Escape") onClose?.();
 };
 window.addEventListener("keydown", onKey);
 return () => window.removeEventListener("keydown", onKey);
 }, [onClose]);

 const sizeClass =
 size === "lg" ? styles.modalLg : size === "xl" ? styles.modalXl : "";

 return (
 <div className={styles.backdrop} onClick={onClose} role="presentation">
 <div
 className={`${styles.modal} ${sizeClass}`}
 onClick={(e) => e.stopPropagation()}
 role="dialog"
 aria-modal="true"
 aria-label={title}
 >
 <div className={styles.header}>
 <h2 className={styles.title}>{title}</h2>
 <button type="button" className={styles.close} onClick={onClose} aria-label="Close">
 <svg viewBox="0 0 24 24" aria-hidden="true">
 <path d="M6 6l12 12M6 18L18 6" />
 </svg>
 </button>
 </div>
 <div className={styles.body}>{children}</div>
 {footer && <div className={styles.footer}>{footer}</div>}
 </div>
 </div>
 );
}
