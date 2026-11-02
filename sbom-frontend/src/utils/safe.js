/**
 * Defensive helpers for handing untrusted data to UI components.
 *
 * Background: several endpoints can return error objects or
 * non-array payloads (e.g. on 4xx/5xx the axios catch hands us an
 * Error). Passing those straight to <DataTable rows={…} /> throws
 * "rows.map is not a function". Wrapping with these helpers keeps
 * the rest of the page rendering.
 */

export function safeArray(value) {
 if (Array.isArray(value)) return value;
 if (value == null) return [];
 // Some backends wrap arrays in { data: [...] } or { rows: [...] };
 // try a few common shapes before giving up.
 if (Array.isArray(value.data)) return value.data;
 if (Array.isArray(value.rows)) return value.rows;
 if (Array.isArray(value.results)) return value.results;
 return [];
}

export function safeObject(value) {
 if (value && typeof value === "object" && !Array.isArray(value)) return value;
 return null;
}
