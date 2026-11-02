import styles from "./Button.module.css";

/**
 * Standard button. Variants:
 * - primary (default): solid blue
 * - secondary: white with border
 * - danger: solid red
 * - ghost: text-only, no background
 *
 * Sizes: "sm" | "md" (default) | "lg". Pass {@code leadingIcon} or
 * {@code trailingIcon} as ReactNode (e.g. inline SVG) to decorate.
 */
export default function Button({
 variant = "primary",
 size = "md",
 type = "button",
 leadingIcon,
 trailingIcon,
 block = false,
 className = "",
 children,
 ...rest
}) {
 const cls = [
 styles.btn,
 styles[variant],
 size === "sm" ? styles.sm : size === "lg" ? styles.lg : "",
 block ? styles.block : "",
 className,
 ]
 .filter(Boolean)
 .join(" ");

 return (
 <button type={type} className={cls} {...rest}>
 {leadingIcon}
 {children}
 {trailingIcon}
 </button>
 );
}
