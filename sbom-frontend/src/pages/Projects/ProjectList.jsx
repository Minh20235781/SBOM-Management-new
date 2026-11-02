import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import PageHeader from "../../components/shared/PageHeader";
import DataTable from "../../components/shared/DataTable";
import Button from "../../components/shared/Button";
import StatusBadge from "../../components/shared/StatusBadge";
import Modal from "../../components/shared/Modal";
import ErrorBanner from "../../components/shared/ErrorBanner";
import ProjectFormModal from "../../components/modals/ProjectFormModal";
import projectApi from "../../api/projectApi";
import { safeArray } from "../../utils/safe";

/**
 * Project list using the new design system. Clicking a row
 * navigates to the project workspace; action buttons in the
 * "Actions" column open the create/edit modal.
 *
 * The previous per-row Delete button was removed: the backend
 * always refused deletion once any package was linked, so the
 * action was effectively dead. To start over, open a project,
 * go to Settings → Reset project data, then run a fresh Trivy
 * scan.
 */
export default function ProjectList() {
    const navigate = useNavigate();
    const [projects, setProjects] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [modal, setModal] = useState(null);
    const [working, setWorking] = useState(false);

    const load = async () => {
        setLoading(true);
        setError(null);
        try {
            setProjects(safeArray(await projectApi.list()));
        } catch (e) {
            setError(e?.response?.data?.message || e?.message || "Failed to load projects");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        load();
    }, []);

    const handleSave = async (payload) => {
        setWorking(true);
        try {
            if (modal?.mode === "edit") {
                await projectApi.update(modal.initial.id, payload);
            } else {
                await projectApi.create(payload);
            }
            setModal(null);
            await load();
        } finally {
            setWorking(false);
        }
    };

    const columns = [
        {
            key: "name",
            header: "Name",
            render: (p) => (
                <div>
                    <div style={{ fontWeight: "var(--weight-semibold)", color: "var(--text-primary)" }}>{p.name}</div>
                    {p.description && (
                        <div style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", marginTop: 2 }}>
                            {p.description}
                        </div>
                    )}
                </div>
            ),
        },
        { key: "status", header: "Status", width: 120, render: (p) => <StatusBadge status={p.status} /> },
        { key: "version", header: "Version", width: 100, align: "right", render: (p) => `v${p.version}` },
        { key: "packageCount", header: "Packages", width: 110, align: "right", render: (p) => p.packageCount ?? "—" },
        {
            key: "createdAt",
            header: "Created",
            width: 200,
            render: (p) => (p.createdAt ? new Date(p.createdAt).toLocaleString() : "—"),
        },
        {
            key: "actions",
            header: "",
            width: 120,
            align: "right",
            render: (p) => (
                <div style={{ display: "inline-flex", gap: 6 }} onClick={(e) => e.stopPropagation()}>
                    <Button size="sm" variant="secondary" onClick={() => setModal({ mode: "edit", initial: p })}>Edit</Button>
                </div>
            ),
        },
    ];

    return (
        <div>
            <PageHeader
                title="Projects"
                description="Each project groups one or more modules, repository configs, and SBOM files."
                actions={<Button variant="primary" onClick={() => setModal({ mode: "create" })}>+ New Project</Button>}
            />
            <ErrorBanner error={error} />
            <DataTable
                columns={columns}
                rows={projects}
                loading={loading}
                onRowClick={(p) => navigate(`/projects/${p.id}`)}
                emptyTitle="No projects yet"
                emptyHint="Create your first project to start scanning SBOMs."
            />
            {(modal?.mode === "create" || modal?.mode === "edit") && (
                <ProjectFormModal initial={modal.initial} onClose={() => !working && setModal(null)} onSave={handleSave} />
            )}
        </div>
    );
}
