import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";
import styles from "./AppLayout.module.css";

/**
 * Application shell used by every authenticated page. Lays out
 * the persistent Sidebar on the left, a Topbar across the top, and
 * a scrollable content area for the active route.
 *
 * Uses react-router's {@link Outlet} because AppLayout is mounted
 * as a layout route in App.jsx — child routes render through Outlet,
 * NOT through a `children` prop (which would always be undefined
 * in the layout-route pattern).
 */
export default function AppLayout() {
 return (
 <div className={styles.layout}>
 <Sidebar />
 <div className={styles.main}>
 <Topbar />
 <div className={styles.content}>
 <Outlet />
 </div>
 </div>
 </div>
 );
}
