import styles from "./PageHeader.module.css";

/**
 * Standard page header: a title + optional description on the left,
 * an actions slot on the right. The actions slot accepts any
 * ReactNode so callers can drop in buttons, filters, etc.
 */
export default function PageHeader({ title, description, actions }) {
 return (
 <div className={styles.header}>
 <div className={styles.titleBlock}>
 <h1 className={styles.title}>{title}</h1>
 {description && <p className={styles.description}>{description}</p>}
 </div>
 {actions && <div className={styles.actions}>{actions}</div>}
 </div>
 );
}
