import { useEffect, useState } from "react";
import Modal from "../shared/Modal";
import Button from "../shared/Button";
import { Field, Input, Textarea, Select } from "../shared/Form";

/**
 * Create / edit form for a Project, wrapped in a Modal. The parent
 * supplies {@code initial} (edit) or nothing (create) and an
 * {@code onSave(payload)} handler. The modal handles its own
 * validation, error display, and submit state.
 */
export default function ProjectFormModal({ initial, onClose, onSave }) {
 const isEdit = Boolean(initial);
 const [name, setName] = useState(initial?.name ?? "");
 const [description, setDescription] = useState(initial?.description ?? "");
 const [status, setStatus] = useState(initial?.status ?? "ACTIVE");
 const [saving, setSaving] = useState(false);
 const [error, setError] = useState(null);

 useEffect(() => {
 setName(initial?.name ?? "");
 setDescription(initial?.description ?? "");
 setStatus(initial?.status ?? "ACTIVE");
 }, [initial]);

 const submit = async (e) => {
 e?.preventDefault();
 if (!name.trim()) {
 setError("Name is required");
 return;
 }
 setSaving(true);
 setError(null);
 try {
 await onSave({ name: name.trim(), description, status });
 } catch (err) {
 setError(err?.response?.data?.message || err?.message || "Save failed");
 } finally {
 setSaving(false);
 }
 };

 return (
 <Modal
 title={isEdit ? `Edit "${initial.name}"` : "New Project"}
 onClose={onClose}
 size="md"
 footer={
 <>
 <Button variant="secondary" onClick={onClose} disabled={saving}>
 Cancel
 </Button>
 <Button
 variant="primary"
 onClick={submit}
 disabled={saving || !name.trim()}
 >
 {saving ? "Saving…" : isEdit ? "Save changes" : "Create project"}
 </Button>
 </>
 }
 >
 <form onSubmit={submit} noValidate>
 {error && (
 <div
 style={{
 padding: "10px 12px",
 background: "var(--color-danger-soft)",
 color: "var(--color-danger)",
 borderRadius: "var(--radius-md)",
 marginBottom: 16,
 fontSize: "var(--text-sm)",
 }}
 >
 {error}
 </div>
 )}

 <Field label="Name" required htmlFor="proj-name" error={!name.trim() ? null : null}>
 <Input
 id="proj-name"
 value={name}
 onChange={(e) => setName(e.target.value)}
 maxLength={200}
 autoFocus
 placeholder="e.g. payment-service"
 />
 </Field>

 <Field label="Description" htmlFor="proj-desc" hint="Optional. A short summary of what this project covers.">
 <Textarea
 id="proj-desc"
 value={description}
 onChange={(e) => setDescription(e.target.value)}
 maxLength={1000}
 placeholder="Service X handles payments and billing…"
 />
 </Field>

 <Field label="Status" htmlFor="proj-status">
 <Select id="proj-status" value={status} onChange={(e) => setStatus(e.target.value)}>
 <option value="ACTIVE">Active</option>
 <option value="ARCHIVED">Archived</option>
 </Select>
 </Field>
 </form>
 </Modal>
 );
}
