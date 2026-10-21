import React from "react";
import { useQuery } from "@tanstack/react-query";
import { api, downloadCollectorPackage } from "./api";
import { useToast } from "./components/toast";
import { DataTable, EmptyState, ErrorState, Notice, humanizeLabel } from "./ui";
import { useUser } from "./user_context";

type GuidePackage = {
  os: string;
  filename: string;
  available: boolean;
  install_command: string;
  download_path?: string;
};

type InstallGuide = {
  id: string;
  title: string;
  summary: string;
  components?: string[];
  commands: Record<string, string>;
  notes?: string[];
  packages_os?: string[];
};

export type CollectorGuideResponse = {
  gateway_url: string;
  registry_url: string;
  tenant_id: string;
  wazuh_manager: string;
  wazuh_manager_reachable: boolean;
  secrets_revealed: boolean;
  missing_secrets: string[];
  guides: InstallGuide[];
  packages: GuidePackage[];
};

function CopyCommand({ label, command }: { label: string; command: string }) {
  const toast = useToast();
  return (
    <div style={{ marginBottom: "0.75rem" }}>
      <div className="section-head" style={{ marginBottom: "0.25rem" }}>
        <strong>{label}</strong>
        <button
          type="button"
          className="secondary compact"
          onClick={() => {
            void navigator.clipboard.writeText(command).then(
              () => toast.push("Copied to clipboard", "ok"),
              () => toast.push("Copy failed", "bad"),
            );
          }}
        >
          Copy
        </button>
      </div>
      <pre className="code-block">{command}</pre>
    </div>
  );
}

export function CollectorInstallGuides({ showDownloads = true }: { showDownloads?: boolean }) {
  const toast = useToast();
  const user = useUser();
  const isAdmin = user.role === "admin";
  const [reveal, setReveal] = React.useState(false);
  const guide = useQuery({
    queryKey: ["collectors-guide", reveal],
    queryFn: () => api<CollectorGuideResponse>(reveal ? "/collectors/guide?reveal=true" : "/collectors/guide"),
    // Revealed secrets must not linger in the query cache after hiding.
    gcTime: reveal ? 0 : undefined,
  });
  const [downloadBusy, setDownloadBusy] = React.useState<string | null>(null);

  async function onDownload(osName: string) {
    setDownloadBusy(osName);
    try {
      await downloadCollectorPackage(osName);
      toast.push(`Downloaded ${osName} collector package`, "ok");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "Download failed", "bad");
    } finally {
      setDownloadBusy(null);
    }
  }

  const data = guide.data;
  return (
    <>
      <ErrorState error={guide.error} />
      {!data ? null : (
        <>
          <div className="section-head">
            <p className="muted">
              Gateway <code>{data.gateway_url}</code> · Registry <code>{data.registry_url}</code> · Tenant{" "}
              <code>{data.tenant_id}</code> · Wazuh manager <code>{data.wazuh_manager}</code>
            </p>
            {isAdmin ? (
              <button type="button" className="secondary compact" onClick={() => setReveal((value) => !value)}>
                {reveal ? "Hide enrollment secrets" : "Reveal enrollment secrets"}
              </button>
            ) : null}
          </div>
          {!data.secrets_revealed ? (
            <p className="muted">
              Ingest key, registry key, and Wazuh registration password are masked
              {isAdmin ? "; reveal them to copy ready-to-run commands (the reveal is audited)." : "; an administrator can reveal them."}
            </p>
          ) : null}
          {data.missing_secrets.length ? (
            <Notice>
              Not configured on this deployment: {data.missing_secrets.map((name) => humanizeLabel(name.replace(/_/g, " "))).join(", ")}.
            </Notice>
          ) : null}
          {!data.wazuh_manager_reachable ? (
            <Notice>
              The Wazuh manager address is loopback-only; set WAZUH_MANAGER_ADDRESS so agents on other hosts can enroll.
            </Notice>
          ) : null}
          {data.guides.map((item) => (
            <section className="card" key={item.id} style={{ marginBottom: "1rem" }}>
              <div className="section-head">
                <div>
                  <span className="section-kicker">Enrollment</span>
                  <h2>{item.title}</h2>
                </div>
              </div>
              <p className="muted">{item.summary}</p>
              {item.components?.length ? (
                <p className="muted">
                  <strong>Components:</strong> {item.components.join(", ")}
                </p>
              ) : null}
              {Object.entries(item.commands).map(([key, command]) => (
                <CopyCommand key={key} label={humanizeLabel(key.replace(/_/g, " "))} command={command} />
              ))}
              {item.notes?.map((note) => (
                <p className="muted" key={note}>
                  {note}
                </p>
              ))}
            </section>
          ))}
          {showDownloads ? (
            <section className="card">
              <div className="section-head">
                <div>
                  <span className="section-kicker">Packages</span>
                  <h2>osquery + shipper ZIP downloads</h2>
                </div>
              </div>
              <DataTable
                columns={[
                  { key: "os", label: "OS", render: (row: GuidePackage) => humanizeLabel(row.os) },
                  { key: "install_command", label: "Install (after unzip)", clip: true },
                  {
                    key: "download",
                    label: "Download",
                    render: (row: GuidePackage) => (
                      <button
                        type="button"
                        className="secondary compact"
                        disabled={!row.available || downloadBusy === row.os}
                        onClick={() => void onDownload(row.os)}
                      >
                        {downloadBusy === row.os ? "Downloading…" : row.filename}
                      </button>
                    ),
                  },
                ]}
                rows={data.packages}
                rowKey={(row: GuidePackage) => row.os}
                empty={
                  <EmptyState
                    title="Collector packages unavailable"
                    description="Mount detection/collectors into the API or rebuild the web image."
                    compact
                  />
                }
              />
            </section>
          ) : null}
        </>
      )}
    </>
  );
}
