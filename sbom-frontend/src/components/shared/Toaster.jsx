import { Toaster as HotToaster, toast } from "react-hot-toast";

/**
 * Global toast host. Drop this once near the root (inside
 * the router) and call the {@link toast} helpers from any
 * component to surface a quick confirmation or error.
 *
 * We restyle the container so the toast stack matches the
 * rest of the dashboard rather than the library's
 * default pastel — rounded card on the top-right, brand
 * colours, a 3px left rail that signals success/error/
 * info at a glance.
 */
export default function Toaster() {
  return (
    <HotToaster
      position="top-right"
      gutter={12}
      toastOptions={{
        duration: 3500,
        className: "sbom-toast",
        style: {
          background: "var(--bg-surface)",
          color: "var(--text-primary)",
          border: "1px solid var(--border-default)",
          borderRadius: "var(--radius-md)",
          boxShadow: "var(--shadow-md)",
          padding: "12px 16px",
          fontSize: "var(--text-sm)",
          maxWidth: 420,
        },
        success: {
          iconTheme: { primary: "#15803d", secondary: "var(--bg-surface)" },
        },
        error: {
          duration: 6000,
          iconTheme: { primary: "#b91c1c", secondary: "var(--bg-surface)" },
        },
      }}
    />
  );
}

export { toast };
