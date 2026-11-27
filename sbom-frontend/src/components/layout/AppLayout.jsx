import { Outlet } from "react-router-dom";
import { useState } from "react";
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
 const [navigationOpen, setNavigationOpen] = useState(false);
 return (
 <div className={styles.layout}>
 <button className={styles.menuToggle} aria-controls="app-navigation" aria-expanded={navigationOpen}
   onClick={() => setNavigationOpen(!navigationOpen)}>{navigationOpen ? "Đóng menu" : "☰ Menu"}</button>
 <div id="app-navigation" className={navigationOpen ? styles.openNavigation : styles.navigation}
   onClick={event => { if (event.target.closest("a")) setNavigationOpen(false); }}>
   <Sidebar />
 </div>
 <div className={styles.main}>
 <Topbar />
 <div className={styles.content}>
 <Outlet />
 </div>
 </div>
 </div>
 );
}
