import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Vite dev server proxies every /api/* request to the Spring
// backend on :8080. Without this, requests to /api/* would
// fall through to the SPA's index.html (a HTML document), and
// any code that JSON.parse()s the response would crash.
//
// /gnn-inference/* is forwarded to the standalone Python GNN
// service on :8000 (see gnn-training/api/server.py). The
// Spring explainability endpoint wraps the Python call and
// reformats the payload, but the Java→Python payload shape
// was missing the `features` block the loader expects, so we
// call Python directly from the GNN page when it's reachable.
//
// For production builds, the same proxies are expected to be
// configured at the reverse-proxy level (nginx, Caddy, etc).
export default defineConfig({
 plugins: [react()],
 server: {
 proxy: {
 '/api': {
 target: 'http://localhost:8080',
 changeOrigin: true,
 },
 '/gnn-inference': {
 target: 'http://localhost:8000',
 changeOrigin: true,
 rewrite: (path) => path.replace(/^\/gnn-inference/, ''),
 },
 },
 },
})
