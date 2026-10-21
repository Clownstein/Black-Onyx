/**
 * Detection-plane workflows in the Black Onyx shell.
 * Pages live under ./detection/pages and call /api/v1/detection/* BFF routes.
 */
import React from "react";
import { Link, Navigate, useParams } from "react-router-dom";
import "./detection/styles.css";
import { Overview } from "./detection/pages/Overview";
import { Incidents } from "./detection/pages/Incidents";
import { IncidentDetail } from "./detection/pages/IncidentDetail";
import { AssetDetail } from "./detection/pages/AssetDetail";
import { Findings } from "./detection/pages/Findings";
import { Hunt } from "./detection/pages/Hunt";
import { Malware } from "./detection/pages/Malware";
import { AttackCoverage } from "./detection/pages/AttackCoverage";
import { Models } from "./detection/pages/Models";
import { Services } from "./detection/pages/Services";
import { Metrics } from "./detection/pages/Metrics";
import { Network } from "./detection/pages/Network";
import { CodeChanges } from "./detection/pages/CodeChanges";
import { DataHealth } from "./detection/pages/DataHealth";
import { ResponseQueue } from "./detection/pages/ResponseQueue";
import { SecurityProfiles } from "./detection/pages/SecurityProfiles";

function Shell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="detection-console">
      <div className="section-head">
        <div>
          <span className="section-kicker">Detection</span>
          <h1>{title}</h1>
          <p className="muted">Detection spine — incidents, hunt, SOAR, and modality views.</p>
        </div>
        <div className="actions">
          <Link className="button ghost compact" to="/detection">Overview</Link>
          <Link className="button ghost compact" to="/incidents">Incidents</Link>
          <Link className="button ghost compact" to="/hunt">Hunt</Link>
          <Link className="button ghost compact" to="/response-queue">Response</Link>
        </div>
      </div>
      {children}
    </div>
  );
}

export function DetectionOverviewWorkflow() {
  return <Shell title="Detection overview"><Overview /></Shell>;
}
export function IncidentsWorkflow() {
  return <Shell title="Incidents"><Incidents /></Shell>;
}
export function IncidentDetailWorkflow() {
  const { id } = useParams();
  return <Shell title={`Incident ${id || ""}`}><IncidentDetail /></Shell>;
}
export function AssetDetailWorkflow() {
  const { id } = useParams();
  return <Shell title={`Asset ${id || ""}`}><AssetDetail /></Shell>;
}
export function FindingsWorkflow() {
  return <Shell title="Findings"><Findings /></Shell>;
}
export function HuntWorkflow() {
  return <Shell title="Hunt"><Hunt /></Shell>;
}
export function MalwareWorkflow() {
  return <Shell title="Malware"><Malware /></Shell>;
}
export function AttackCoverageWorkflow() {
  return <Shell title="ATT&CK coverage"><AttackCoverage /></Shell>;
}
export function ModelsWorkflow() {
  return <Shell title="Models"><Models /></Shell>;
}
export function DetectionServicesWorkflow() {
  return <Shell title="Detection services"><Services /></Shell>;
}
export function DetectionMetricsWorkflow() {
  return <Shell title="Metrics modality"><Metrics /></Shell>;
}
export function DetectionNetworkWorkflow() {
  return <Shell title="Network modality"><Network /></Shell>;
}
export function DetectionCodeChangesWorkflow() {
  return <Shell title="Code changes"><CodeChanges /></Shell>;
}
export function DataHealthWorkflow() {
  return <Shell title="Data health"><DataHealth /></Shell>;
}
export function ResponseQueueWorkflow() {
  return <Shell title="Response queue"><ResponseQueue /></Shell>;
}
export function SecurityProfilesWorkflow() {
  return <Shell title="Security profiles"><SecurityProfiles /></Shell>;
}
export function DetectionAdminWorkflow() { return <Navigate to="/admin" replace />; }
