import { useEffect, useId, useRef } from "react";
import styles from "./NodeDetailsDialog.module.css";

export default function NodeDetailsDialog({ title, onClose, children }) {
  const dialog = useRef(null);
  const titleId = useId();
  useEffect(() => {
    const element = dialog.current;
    if (!element.open) element.showModal();
    return () => element.close();
  }, []);

  return (
    <dialog ref={dialog} className={styles.dialog} aria-labelledby={titleId} onCancel={(event) => {
      event.preventDefault();
      onClose();
    }}>
      <header className={styles.header}>
        <h2 id={titleId}>{title}</h2>
        <button type="button" onClick={onClose} autoFocus>Đóng</button>
      </header>
      <div className={styles.body}>{children}</div>
    </dialog>
  );
}
