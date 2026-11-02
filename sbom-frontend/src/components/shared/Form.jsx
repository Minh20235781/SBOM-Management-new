import styles from "./Form.module.css";

/**
 * Reusable form primitives that match the design tokens. These
 * wrap the native input/textarea/select elements so consumers can
 * keep using standard form libraries (Formik, react-hook-form)
 * without re-theming.
 */

export function Field({ label, hint, required, error, children, htmlFor }) {
 return (
 <div className={styles.field}>
 {label && (
 <label className={styles.label} htmlFor={htmlFor}>
 {label}
 {required && <span className={styles.required}>*</span>}
 </label>
 )}
 {children}
 {hint && !error && <div className={styles.hint}>{hint}</div>}
 {error && <div className={styles.error}>{error}</div>}
 </div>
 );
}

export function Input({ id, error, ...rest }) {
 return (
 <input
 id={id}
 className={styles.input}
 aria-invalid={error ? "true" : undefined}
 {...rest}
 />
 );
}

export function Textarea({ id, error, rows = 3, ...rest }) {
 return (
 <textarea
 id={id}
 rows={rows}
 className={styles.textarea}
 aria-invalid={error ? "true" : undefined}
 {...rest}
 />
 );
}

export function Select({ id, error, children, ...rest }) {
 return (
 <select id={id} className={styles.select} aria-invalid={error ? "true" : undefined} {...rest}>
 {children}
 </select>
 );
}

export function FormRow({ children }) {
 return <div className={styles.row}>{children}</div>;
}
