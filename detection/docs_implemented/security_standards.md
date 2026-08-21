# Security Standards, Best Practices, and Industry Requirements

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).


Research compiled July 2026 from NIST, CIS, OWASP (ASVS / WSTG), PCI SSC, ISO, AICPA, ISACA, CSA, MITRE, and industry compliance guidance.

Use the checklists below as **verification agendas** when assessing a network, server/host, web application/API, identity plane, or data path. Items marked **[auto]** are good candidates for automated scanning or continuous telemetry in a platform like AutoAnalyzer; items marked **[manual]** typically need evidence review, interview, or policy attestation.

---

## How to read the checklists

| Surface | Typical evidence |
| --- | --- |
| **Network** | Firewall/ACL rules, flow logs, segmentation diagrams, DNS, VPN, wireless, OT gateways |
| **Server / host** | OS hardening, packages, services, agents, local accounts, disk encryption, backups |
| **Web app / API** | Authn/z, input validation, headers, TLS, secrets, dependency/SCA, DAST/SAST |
| **Identity** | IdP config, MFA, RBAC, privileged access, session policy, joiner/mover/leaver |
| **Data** | Classification, encryption, retention, DLP, backups, key management |
| **Detect / respond** | Logging coverage, SIEM rules, IR runbooks, restore tests |

---

## Part 1 — Top 10 Security Standards and Best Practices

---

### 1. NIST Cybersecurity Framework (CSF) 2.0

| | |
| --- | --- |
| **Publisher** | U.S. NIST |
| **Type** | Voluntary risk-management framework |
| **Focus** | Govern → Identify → Protect → Detect → Respond → Recover |
| **Official** | [nist.gov/cyberframework](https://www.nist.gov/cyberframework) |

#### Checklist — Govern / Identify

- [ ] **[manual]** Cybersecurity roles, risk appetite, and policies are documented and owned
- [ ] **[manual]** Asset inventory exists for hardware, software, cloud, and data stores (owners assigned)
- [ ] **[auto]** Unauthorized / unmanaged assets are detectable on the network
- [ ] **[manual]** Business-critical services and data flows are mapped (including suppliers)
- [ ] **[manual]** Risk assessments are current; residual risk accepted by an accountable owner
- [ ] **[manual]** Supply-chain / third-party risks are inventoried and reviewed on a cadence

#### Checklist — Protect (network / server / app)

- [ ] **[auto]** Baseline secure configurations applied to servers, network devices, and endpoints
- [ ] **[auto]** Unused services/ports closed; management planes not exposed to the internet
- [ ] **[auto]** MFA enforced for remote and privileged access
- [ ] **[auto]** TLS 1.2+ on external services; weak ciphers disabled
- [ ] **[auto]** Web apps send security headers (HSTS, CSP where appropriate, X-Content-Type-Options)
- [ ] **[manual]** Change management covers security-relevant changes
- [ ] **[auto]** Backups exist for critical systems; immutability / offline copies considered

#### Checklist — Detect / Respond / Recover

- [ ] **[auto]** Centralized logging for auth, network edge, servers, and critical apps
- [ ] **[auto]** Alerts for brute force, anomalous egress, privilege escalation, malware indicators
- [ ] **[manual]** Incident response plan with roles, contacts, and escalation paths
- [ ] **[manual]** Tabletop or technical IR exercise within the last 12 months
- [ ] **[manual]** Recovery time/point objectives defined and restore tested

---

### 2. ISO/IEC 27001 and ISO/IEC 27002

| | |
| --- | --- |
| **Publisher** | ISO / IEC |
| **Type** | Certifiable ISMS + control guidance |
| **Focus** | Risk-based information security management |
| **Official** | [iso.org](https://www.iso.org/standard/27001) |

#### Checklist — ISMS / governance

- [ ] **[manual]** Scope of the ISMS is defined (systems, sites, cloud accounts, suppliers)
- [ ] **[manual]** Information security policy approved by leadership
- [ ] **[manual]** Risk assessment methodology, risk register, and Statement of Applicability exist
- [ ] **[manual]** Internal audit and management review occur on schedule
- [ ] **[manual]** Continual improvement / nonconformity tracking is active

#### Checklist — Network

- [ ] **[auto]** Network segregation between trust zones (user, app, data, management, guest)
- [ ] **[auto]** Firewall rules reviewed; deny-by-default; documented business justification
- [ ] **[auto]** Remote access via VPN or Zero Trust access with MFA
- [ ] **[auto]** Wireless: WPA2/WPA3-Enterprise; guest isolation; rogue AP monitoring
- [ ] **[manual]** Cryptographic controls for sensitive links (site-to-site, partner connections)

#### Checklist — Server / host

- [ ] **[auto]** Hardened baselines (CIS Benchmarks or equivalent) for OS images
- [ ] **[auto]** Patch management SLA defined and measurable (critical vs routine)
- [ ] **[auto]** Malware protection / EDR deployed and reporting
- [ ] **[auto]** Privileged local accounts inventoried; default passwords removed
- [ ] **[auto]** Disk encryption on laptops and sensitive servers where required
- [ ] **[manual]** Capacity / availability monitoring aligned to SLA

#### Checklist — Web app / API / development

- [ ] **[auto]** Secure SDLC: SAST/SCA on CI; secrets scanning on commits
- [ ] **[auto]** No hardcoded credentials, API keys, or private keys in repos
- [ ] **[auto]** Input validation / parameterized queries (injection resistance)
- [ ] **[auto]** Authentication and session management meet policy (timeouts, lockout)
- [ ] **[manual]** Supplier / SaaS contracts include security and breach notification clauses
- [ ] **[manual]** Secure disposal of media and cloud resources at end of life

---

### 3. CIS Critical Security Controls (v8.1)

| | |
| --- | --- |
| **Publisher** | Center for Internet Security |
| **Type** | Prioritized safeguards (18 controls; IG1–IG3) |
| **Focus** | Practical technical defense |
| **Official** | [cisecurity.org/controls](https://www.cisecurity.org/controls/cis-controls-list) |

#### Checklist — Asset & software inventory (Controls 1–2)

- [ ] **[auto]** Complete inventory of endpoints, servers, network gear, cloud instances, IoT
- [ ] **[auto]** Unauthorized devices trigger alert or quarantine workflow
- [ ] **[auto]** Authorized software inventory; application allowlisting on high-value hosts (IG2+)
- [ ] **[auto]** Unauthorized software detectable and removable

#### Checklist — Data, config, accounts (Controls 3–6)

- [ ] **[manual]** Data classification labels and handling rules
- [ ] **[auto]** Encryption for sensitive data at rest and in transit
- [ ] **[auto]** Secure configuration baselines enforced (IaC / MDM / config management)
- [ ] **[auto]** Unique accounts; no shared admin credentials
- [ ] **[auto]** MFA for all administrative and remote access
- [ ] **[auto]** Privileged access time-bound; just-in-time where feasible
- [ ] **[auto]** Access reviews for sensitive roles on a defined cadence

#### Checklist — Vuln, logging, malware, recovery (Controls 7–11)

- [ ] **[auto]** Continuous vulnerability scanning of internet-facing and internal assets
- [ ] **[auto]** Remediation SLAs tracked (critical/high)
- [ ] **[auto]** Audit logs collected from servers, IdP, firewalls, endpoints, cloud control planes
- [ ] **[auto]** Log retention meets policy; clocks NTP-synced
- [ ] **[auto]** DNS filtering / secure web gateway for malware & phishing URLs (IG1+)
- [ ] **[auto]** Anti-malware / EDR on all applicable assets; signatures/behavior engines current
- [ ] **[auto]** Automated backups; restore tested; ransomware-resistant backup design

#### Checklist — Network & apps (Controls 12–13, 16)

- [ ] **[auto]** Network diagrams current; management interfaces isolated
- [ ] **[auto]** Network monitoring: IDS/IPS or flow analytics; alert on anomalous traffic
- [ ] **[auto]** Email security: SPF/DKIM/DMARC; attachment/URL detonation where available
- [ ] **[auto]** Application security: dependency scanning, secret scanning, secure coding standards
- [ ] **[auto]** WAF or equivalent for public web apps (IG2+)
- [ ] **[manual]** Incident response plan + tabletop (Control 17)
- [ ] **[manual]** Service provider security assessments (Control 15)

---

### 4. SOC 2 (Trust Services Criteria)

| | |
| --- | --- |
| **Publisher** | AICPA (independent CPA attestation) |
| **Type** | Assurance report (Type I / Type II) |
| **Focus** | Security (+ optional Availability, Processing Integrity, Confidentiality, Privacy) |

#### Checklist — Security (common criteria)

- [ ] **[manual]** Control environment: policies, org structure, board/oversight communication
- [ ] **[manual]** Risk assessment includes fraud and cybersecurity scenarios
- [ ] **[auto]** Logical access: unique IDs, MFA, RBAC, timely revocation on termination
- [ ] **[auto]** System boundaries documented; production access restricted
- [ ] **[auto]** Change management: tracked tickets, approvals, CI/CD gates for prod
- [ ] **[auto]** Encryption in transit (TLS) and at rest for customer data stores
- [ ] **[auto]** Vulnerability management with scanning and remediation evidence
- [ ] **[auto]** Security monitoring / alerting with on-call response
- [ ] **[manual]** Vendor risk reviews for subprocessors holding customer data
- [ ] **[manual]** Incident response and customer notification procedures

#### Checklist — Availability / Confidentiality / Privacy (if in scope)

- [ ] **[auto]** Capacity monitoring, redundancy, failover tested
- [ ] **[auto]** Backup and restore drills with evidence retained for audit period
- [ ] **[manual]** Data retention / deletion aligned to customer contracts
- [ ] **[auto]** Segregation of customer data in multi-tenant systems
- [ ] **[manual]** Privacy notices, consent/opt-out, DSR (data subject request) process if Privacy in scope

#### Checklist — Web app / API (auditor-friendly evidence)

- [ ] **[auto]** Production secrets in vault/KMS — not in code or CI logs
- [ ] **[auto]** Admin interfaces MFA-protected and IP-restricted where possible
- [ ] **[auto]** Audit trail of admin actions retained for Type II period
- [ ] **[manual]** Penetration test or equivalent annual assessment with remediation tracking

---

### 5. PCI DSS v4.0

| | |
| --- | --- |
| **Publisher** | PCI Security Standards Council |
| **Type** | Mandatory for cardholder data |
| **Focus** | Cardholder Data Environment (CDE) |
| **Official** | [pcisecuritystandards.org](https://www.pcisecuritystandards.org/) |

#### Checklist — Network (Req 1–2)

- [ ] **[auto]** CDE clearly segmented; firewalls between CDE and untrusted networks
- [ ] **[auto]** Inbound to CDE limited to necessary protocols; outbound restricted
- [ ] **[manual]** Network diagram and data-flow diagram for CHD current
- [ ] **[auto]** No vendor-default passwords on any system in scope
- [ ] **[auto]** Only necessary services enabled on CDE systems

#### Checklist — Protect account data (Req 3–4)

- [ ] **[auto]** No storage of sensitive authentication data after authorization (full track, CVV, PIN)
- [ ] **[auto]** PAN rendered unreadable where stored (tokenization, truncation, strong crypto)
- [ ] **[auto]** Keys managed securely (rotation, dual control / split knowledge as required)
- [ ] **[auto]** Strong cryptography for CHD over open/public networks (TLS)

#### Checklist — Vuln / access / auth (Req 5–8)

- [ ] **[auto]** Anti-malware on applicable systems; kept current
- [ ] **[auto]** Secure development and change control for in-scope apps
- [ ] **[auto]** Vulnerability scans (internal + ASV external quarterly); high issues remediated
- [ ] **[auto]** Penetration testing per v4.0 frequency/scope
- [ ] **[auto]** Unique IDs; MFA for all access into CDE (v4.0 MFA expansions)
- [ ] **[auto]** Strong password/passphrase policy; idle session timeout
- [ ] **[auto]** Access based on job need-to-know; accounts disabled promptly

#### Checklist — Logging, testing, policy (Req 10–12)

- [ ] **[auto]** Audit logs for all CDE access; protected against alteration; time synced
- [ ] **[auto]** Daily log review (or automated equivalents with exception review)
- [ ] **[manual]** Security policy, acceptable use, IR plan; annual risk assessment
- [ ] **[manual]** Security awareness training for personnel
- [ ] **[manual]** Third-party service providers listed; responsibility matrix; compliance evidence

#### Checklist — Web app / e-commerce extras

- [ ] **[auto]** Payment pages: CSP / script integrity controls as required by v4.0 timelines
- [ ] **[auto]** No mixed content; HSTS; secure cookies
- [ ] **[auto]** WAF or equivalent for public payment applications where applicable
- [ ] **[manual]** SAQ vs ROC path correct for merchant/service-provider level

---

### 6. COBIT

| | |
| --- | --- |
| **Publisher** | ISACA |
| **Type** | IT governance / management framework |
| **Focus** | Align IT and security with enterprise goals |

#### Checklist — Governance (evaluate / direct / monitor)

- [ ] **[manual]** IT/security objectives cascade from enterprise strategy
- [ ] **[manual]** Decision rights clear (who approves risk, exceptions, investments)
- [ ] **[manual]** KPIs/KRIs for security reported to leadership (e.g., patch latency, MTTD/MTTR)
- [ ] **[manual]** Assurance activities planned (internal audit, external audit, red team)

#### Checklist — Manage (build / run / monitor) — technical evidence

- [ ] **[manual]** Portfolio of security controls mapped to risks and processes
- [ ] **[auto]** Configuration and change controls produce auditable trails
- [ ] **[auto]** Service availability and security events monitored against targets
- [ ] **[manual]** Third-party and cloud services included in governance scope
- [ ] **[manual]** Lessons learned from incidents feed control improvements
- [ ] **[manual]** Resource/skills gaps for cybersecurity identified and funded

*(COBIT is governance-heavy; pair with CIS/NIST for deep technical checklists.)*

---

### 7. NIST SP 800-53 / FedRAMP

| | |
| --- | --- |
| **Publisher** | NIST / FedRAMP PMO |
| **Type** | Control catalog + cloud authorization baselines |
| **Focus** | Federal-grade system security (Low / Moderate / High) |

#### Checklist — Access control & identification (AC / IA)

- [ ] **[auto]** Account types managed; shared accounts prohibited for interactive use
- [ ] **[auto]** Least privilege; privileged functions separated
- [ ] **[auto]** Session lock / termination; remote access controls
- [ ] **[auto]** MFA for network and privileged access; authenticator management
- [ ] **[auto]** Device identification where required by baseline

#### Checklist — Audit, config, contingency (AU / CM / CP)

- [ ] **[auto]** Auditable events defined; logs protected and retained per policy
- [ ] **[auto]** Baseline configurations; integrity monitoring for critical files
- [ ] **[auto]** Flaw remediation (patching) with tracking
- [ ] **[manual]** Contingency plan; backups; alternate processing tested
- [ ] **[auto]** System component inventory accurate

#### Checklist — Network / system protections (SC / SI)

- [ ] **[auto]** Boundary protection; subnetworks for public services
- [ ] **[auto]** Cryptographic protection using FIPS-validated modules where required
- [ ] **[auto]** Collaborative computing devices controlled; mobile code policy enforced
- [ ] **[auto]** Malicious code protection; system monitoring; software integrity
- [ ] **[auto]** Error handling does not leak sensitive info in web responses

#### Checklist — FedRAMP / cloud extras

- [ ] **[manual]** Authorization boundary and data flows documented
- [ ] **[auto]** Continuous monitoring feeds (vuln, config, inventory) to agency/JAB expectations
- [ ] **[manual]** POA&M for residual findings with dates and owners
- [ ] **[auto]** Customer responsibility matrix published for SaaS/PaaS/IaaS
- [ ] **[manual]** Supply-chain risk (SR) controls for critical components

---

### 8. Zero Trust Architecture (NIST SP 800-207)

| | |
| --- | --- |
| **Publisher** | NIST |
| **Type** | Architectural model |
| **Focus** | Never trust, always verify; assume breach |

#### Checklist — Identity & device

- [ ] **[auto]** Strong identity proofing; phishing-resistant MFA for privileged and remote users
- [ ] **[auto]** Device posture checks (patch level, disk encryption, EDR healthy) before access
- [ ] **[auto]** No broad flat VPN that grants whole-network access after login
- [ ] **[auto]** Continuous re-authentication / re-authorization for sensitive sessions

#### Checklist — Network

- [ ] **[auto]** Micro-segmentation or identity-aware proxy between workloads
- [ ] **[auto]** East-west traffic inspected or controlled (not only north-south)
- [ ] **[auto]** Deny lateral movement defaults between user VLANs and servers
- [ ] **[auto]** Encrypted service-to-service traffic (mTLS) in critical clusters

#### Checklist — Application / data

- [ ] **[auto]** Per-request authorization at the application layer (not just network ACL)
- [ ] **[auto]** Secrets short-lived; workload identity (not long-lived static keys)
- [ ] **[auto]** Data access logged with subject, resource, and decision
- [ ] **[manual]** Policy engine / policy admin / policy enforcement points designed and owned
- [ ] **[auto]** Anomalous access patterns detectable (impossible travel, sudden bulk download)

---

### 9. MITRE ATT&CK

| | |
| --- | --- |
| **Publisher** | MITRE |
| **Type** | Adversary TTP knowledge base |
| **Focus** | Threat-informed detection and defense |
| **Official** | [attack.mitre.org](https://attack.mitre.org/) |

#### Checklist — Coverage & mapping

- [ ] **[manual]** Priority tactics/techniques selected for your crown-jewel threats
- [ ] **[auto]** Detections tagged with technique IDs (e.g., T1110, T1059, T1071)
- [ ] **[manual]** Coverage heatmap maintained (rules vs model vs correlated depth)
- [ ] **[manual]** Gaps accepted with compensating controls or risk acceptance

#### Checklist — Network-oriented techniques

- [ ] **[auto]** T1046 Network Service Discovery — port scans / failed connection bursts
- [ ] **[auto]** T1071 Application Layer Protocol — beaconing / anomalous C2-like flows
- [ ] **[auto]** T1048 Exfiltration Over Alternative Protocol — unusual egress volume/destinations
- [ ] **[auto]** T1090 Proxy — unexpected proxy or tunnel usage
- [ ] **[auto]** T1190 Exploit Public-Facing Application — exploit/WAF/deny spikes

#### Checklist — Host / identity techniques

- [ ] **[auto]** T1110 Brute Force — failed logon bursts
- [ ] **[auto]** T1059 Command / scripting interpreters — unusual PowerShell/bash patterns
- [ ] **[auto]** T1053 Scheduled Task / Job — rare persistence jobs
- [ ] **[auto]** T1547 Boot/Logon Autostart — rare autoruns
- [ ] **[auto]** T1003 Credential Dumping — LSASS/access patterns (where EDR supports)
- [ ] **[auto]** T1021 Remote Services — anomalous RDP/SSH/WinRM

#### Checklist — Web app techniques

- [ ] **[auto]** T1190 / injection classes covered by SAST/DAST and WAF rules
- [ ] **[auto]** T1550 Use Alternate Authentication Material — token theft / session fixation tests
- [ ] **[auto]** T1505 Server Software Component — webshell detection
- [ ] **[manual]** Purple-team exercises validate detections for top techniques

---

### 10. CSA Cloud Controls Matrix (CCM) / Secure Cloud Practices

| | |
| --- | --- |
| **Publisher** | Cloud Security Alliance |
| **Type** | Cloud control framework |
| **Focus** | Shared-responsibility cloud / SaaS security |
| **Official** | [cloudsecurityalliance.org](https://cloudsecurityalliance.org/research/cloud-controls-matrix) |

#### Checklist — Identity & access (IAM)

- [ ] **[auto]** Cloud SSO federated; human long-lived access keys minimized
- [ ] **[auto]** MFA on console and privileged API access
- [ ] **[auto]** IAM policies least-privilege; unused roles/keys aged out
- [ ] **[auto]** Workload identities for compute (instance roles / workload federation)

#### Checklist — Network & infrastructure

- [ ] **[auto]** Security groups / NSGs / firewall rules deny by default
- [ ] **[auto]** Public buckets / blobs inventory; block public access at org level where possible
- [ ] **[auto]** Private connectivity for data planes (PrivateLink / VPC peering / private endpoints)
- [ ] **[auto]** Flow logs / VPC logs enabled and retained
- [ ] **[auto]** Bastion or ZTNA for admin access — no SSH/RDP wide open to `0.0.0.0/0`

#### Checklist — Data / crypto / logging

- [ ] **[auto]** CMEK/CMK where required; key rotation policies
- [ ] **[auto]** Encryption defaults on storage and databases
- [ ] **[auto]** Cloud audit logs (CloudTrail / Activity Log / Admin Activity) immutable sink
- [ ] **[auto]** Guaranteed log delivery to SIEM / lake; alert on logging disabled
- [ ] **[manual]** Shared-responsibility matrix documented per service used

#### Checklist — Web / App / DevOps in cloud

- [ ] **[auto]** Container images scanned; only signed/approved base images in prod
- [ ] **[auto]** Secrets from manager — not env files in images
- [ ] **[auto]** Kubernetes: PSA/PSS, network policies, etcd/API restricted
- [ ] **[auto]** CI/CD OIDC to cloud — short-lived credentials
- [ ] **[manual]** CSP incident notification and support channels tested

---

### Cross-cutting technical checklist (any framework)

#### Network

- [ ] Asset and interface inventory complete
- [ ] Segmentation between user / app / data / management / OT
- [ ] Egress filtering and DNS security
- [ ] TLS everywhere on external and admin paths
- [ ] Continuous flow or packet metadata monitoring

#### Server / host

- [ ] Hardened baseline + drift detection
- [ ] Patch SLA + vulnerability scan closure
- [ ] EDR + host firewall
- [ ] Privileged access controlled and logged
- [ ] Backup + tested restore

#### Web application / API

- [ ] OWASP ASVS-aligned authn/z, session, and crypto checks
- [ ] OWASP WSTG-style tests: info gathering, config, identity, input validation, error handling, crypto, business logic, client-side
- [ ] Security headers, cookie flags, CORS least privilege
- [ ] SAST + SCA + secrets scan in CI; periodic DAST
- [ ] Rate limiting / bot / brute-force protections on login and sensitive APIs

#### Shared

- [ ] MFA, logging, IR plan, vendor risk, security training

---

## Part 2 — Top 10 Specialized Industries and Their Security Requirements

Sector mandates **add** to Part 1 checklists. Reuse the technical items above; focus here on industry-specific must-checks.

---

### 1. Healthcare and Life Sciences (HIPAA / HITECH / HITRUST / FDA devices)

#### Checklist — PHI / ePHI handling

- [ ] **[manual]** Systems inventory that create, receive, maintain, or transmit PHI
- [ ] **[auto]** Access to EHR/PHI systems unique, role-based, logged
- [ ] **[auto]** Automatic logoff / session timeout on clinical workstations
- [ ] **[auto]** Encryption of ePHI at rest and in transit (or documented equivalent alternative)
- [ ] **[manual]** Business Associate Agreements for every vendor touching PHI
- [ ] **[manual]** Risk analysis documented; risk management plan tracked
- [ ] **[manual]** Breach assessment procedure; notification playbooks (patient / HHS / media thresholds)
- [ ] **[auto]** Audit controls: who accessed which record (where EHR supports)
- [ ] **[manual]** Workforce clearance, sanctions, and training records
- [ ] **[auto]** Medical device / IoMT network segmentation; default creds changed
- [ ] **[manual]** FDA cybersecurity documentation for connected device makers (SBOM, update plan)

---

### 2. Financial Services (GLBA / FFIEC / SOX / DORA / NYDFS)

#### Checklist — Customer financial data & ops resilience

- [ ] **[manual]** Written Information Security Program (WISP) / Safeguards Rule program
- [ ] **[auto]** MFA for employees and high-risk customers as required
- [ ] **[auto]** Encryption of customer information in transit and at rest
- [ ] **[manual]** Vendor due diligence + ongoing monitoring for critical ICT providers
- [ ] **[auto]** Anomalous transaction / account-takeover detection hooks
- [ ] **[manual]** Incident notification timelines met (regulator / customer / DORA clocks)
- [ ] **[auto]** Privileged access to core banking / trading systems tightly controlled
- [ ] **[manual]** SOX ITGCs: change management, access to financial reporting systems, backup
- [ ] **[auto]** Immutable / protected logs for trade and account changes
- [ ] **[manual]** Business continuity and cyber resilience testing (failover, ransomware)

---

### 3. Retail / E-commerce / Payments (PCI DSS + privacy)

#### Checklist — Store, POS, and online checkout

- [ ] **[auto]** Full Part 1 PCI DSS checklist applied to CDE
- [ ] **[auto]** POS / payment terminals inventory; tamper inspection process
- [ ] **[auto]** No CHD on corporate email, tickets, or chat
- [ ] **[auto]** E-commerce: payment page script inventory and integrity monitoring (PCI 4.0)
- [ ] **[auto]** Segmented Wi-Fi: card-present networks isolated from guest
- [ ] **[manual]** Privacy notices; consumer rights workflows (CCPA/CPRA/GDPR as applicable)
- [ ] **[auto]** Magstripe / chip / contactless firmware kept current via vendor process

---

### 4. U.S. Federal / Civilian Government (FISMA / FedRAMP / NIST)

#### Checklist — Authorization & continuous monitoring

- [ ] **[manual]** System Security Plan (SSP) current; control inheritance clear
- [ ] **[manual]** ATO / provisional authorization path understood
- [ ] **[auto]** 800-53 baseline controls implemented for impact level
- [ ] **[auto]** Continuous Diagnostics & Monitoring style telemetry (inventory, vuln, config)
- [ ] **[auto]** FIPS-validated crypto where required
- [ ] **[manual]** POA&M hygiene; unresolved high findings escalated
- [ ] **[auto]** TIC / agency egress patterns respected where applicable
- [ ] **[manual]** Supply-chain and software attestation (EO-aligned) for critical software

---

### 5. Defense / DIB (DFARS / NIST 800-171 / CMMC 2.0)

#### Checklist — CUI protection

- [ ] **[manual]** CUI inventory and marking; flow down to subcontractors
- [ ] **[auto]** Access control to CUI systems; FIPS crypto for CUI in transit/at rest
- [ ] **[auto]** Multifactor authentication for network access to CUI
- [ ] **[auto]** Audit logging of CUI access and admin actions; 90-day+ retention as required
- [ ] **[auto]** Media protection / sanitization before reuse or disposal
- [ ] **[manual]** Incident reporting to DoD within contractual timelines
- [ ] **[auto]** Vulnerability scanning and flaw remediation on CUI assets
- [ ] **[manual]** SPRS self-assessment / C3PAO evidence ready for contract level
- [ ] **[auto]** Remote access and wireless constrained for CUI environments
- [ ] **[manual]** Physical access controls for spaces storing CUI systems

---

### 6. Energy / Utilities / Critical Infrastructure (NERC CIP / TSA)

#### Checklist — OT / BES / pipeline-adjacent

- [ ] **[manual]** BES Cyber System / critical asset identification and categorization
- [ ] **[auto]** Electronic security perimeter(s); known access points only
- [ ] **[auto]** Interactive remote access via Intermediate System; MFA
- [ ] **[auto]** Malicious code prevention on applicable Cyber Assets
- [ ] **[auto]** Security patch management with documented exceptions for OT constraints
- [ ] **[manual]** Personnel risk assessments / cyber training for authorized staff
- [ ] **[auto]** OT/IT unidirectional or tightly controlled conduits; no flat plant networks
- [ ] **[auto]** Incident detection with **very short** reporting SLAs (CIP / TSA)
- [ ] **[manual]** Recovery plans for cyber events affecting operations
- [ ] **[auto]** Change control for OT — tested offline before production push

---

### 7. Education (FERPA / EdTech / GLBA aid offices)

#### Checklist — Student data & campus systems

- [ ] **[manual]** Education record definition understood; directory info policy published
- [ ] **[auto]** SIS / LMS access role-based; parent/student portals MFA where available
- [ ] **[manual]** EdTech vendor contracts: data use limits, subprocessors, breach notice
- [ ] **[auto]** No unnecessary PII in public course sites or search-indexable pages
- [ ] **[auto]** Research data with regulated data (HIPAA/export) on isolated environments
- [ ] **[auto]** Payment systems for tuition → PCI checklist
- [ ] **[manual]** Financial aid offices → GLBA Safeguards checklist
- [ ] **[auto]** Alumni / fundraising CRM access reviews

---

### 8. Insurance (state regs / NYDFS / GLBA)

#### Checklist — Policyholder data & cyber program

- [ ] **[manual]** Cybersecurity policy approved by senior officer / board as required
- [ ] **[manual]** Qualified CISO (or equivalent) designated
- [ ] **[auto]** MFA, encryption, audit trails per NYDFS-class requirements where applicable
- [ ] **[auto]** Application security for portals quoting/binding policies
- [ ] **[manual]** Third-party service provider security requirements in contracts
- [ ] **[manual]** Incident notification to DFS/regulators and consumers within deadlines
- [ ] **[auto]** Segregation of claims PII / health data if dual health-insurance exposure
- [ ] **[manual]** Annual certification / reporting completed accurately

---

### 9. Manufacturing / OT / Export-controlled (ITAR/EAR / IEC 62443 / CMMC)

#### Checklist — Plant floor & IP

- [ ] **[auto]** Purdue-style segmentation; engineering workstations controlled
- [ ] **[auto]** No direct internet from PLCs/HMIs; jump hosts for vendors
- [ ] **[manual]** Change windows and rollback for OT patches
- [ ] **[auto]** USB / removable media controls in plants
- [ ] **[manual]** ITAR/EAR technical data access limited to authorized persons / geographies
- [ ] **[auto]** Design IP repositories (PLM/CAD) MFA + DLP egress monitoring
- [ ] **[auto]** Supplier remote access time-bound and monitored
- [ ] **[manual]** If DoD supplier: apply Defense / CMMC checklist
- [ ] **[auto]** Anomalous OT protocol / setpoint change detection where sensors exist

---

### 10. Technology / SaaS / Consumer digital (SOC 2 / ISO / GDPR / CCPA / SEC)

#### Checklist — Product & customer trust

- [ ] **[auto]** Multi-tenant isolation tested (IDOR / cross-tenant access negative tests)
- [ ] **[auto]** Secure SDLC + vulnerability disclosure program
- [ ] **[manual]** DPA / SCCs / transfer mechanisms for EU data
- [ ] **[manual]** Data subject / consumer rights request SLA met
- [ ] **[auto]** Privacy-preserving defaults; retention jobs delete expired data
- [ ] **[auto]** Status page / incident comms process; SEC materiality assessment if public
- [ ] **[auto]** Admin impersonation / support access fully audited
- [ ] **[manual]** Subprocessor list published and updated
- [ ] **[auto]** Production access via SSO + MFA; break-glass accounts monitored

---

## Quick Reference — Industry → Primary Mandates

| Industry | Primary security / privacy mandates |
| --- | --- |
| Healthcare | HIPAA, HITECH, HITRUST (market), FDA (devices) |
| Financial services | GLBA, FFIEC, SOX, DORA (EU), NYDFS |
| Retail / payments | PCI DSS 4.0, privacy laws |
| Federal / civilian gov | FISMA, NIST 800-53, FedRAMP |
| Defense / DIB | DFARS, NIST 800-171, CMMC 2.0 |
| Energy / critical infra | NERC CIP, TSA directives |
| Education | FERPA (+ GLBA/PCI where applicable) |
| Insurance | State regs, NYDFS, GLBA |
| Manufacturing / OT | ITAR/EAR, IEC 62443, CMMC (if DIB) |
| Tech / SaaS / consumer | SOC 2, ISO 27001, GDPR, CCPA/CPRA, SEC (public) |

---

## How Organizations Typically Combine Them

1. **Backbone** — NIST CSF or ISO 27001 for program structure  
2. **Technical priority** — CIS Controls + Zero Trust  
3. **Sector mandates** — HIPAA, PCI, CMMC, NERC CIP, etc.  
4. **Customer trust** — SOC 2 / ISO attestation  
5. **Threat-informed detect** — MITRE ATT&CK-mapped detections  
6. **Cloud overlay** — CSA CCM / FedRAMP shared-responsibility  
7. **Governance** — COBIT-style oversight and KRIs  

---

## Primary Sources Consulted

- [NIST CSF](https://www.nist.gov/cyberframework) · [NIST SP 800-207 Zero Trust](https://www.nist.gov/publications/zero-trust-architecture)
- [CIS Controls list (v8.1)](https://www.cisecurity.org/controls/cis-controls-list)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) · [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/)
- [PCI SSC](https://www.pcisecuritystandards.org/)
- [MITRE ATT&CK](https://attack.mitre.org/) · [CSA CCM](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
- Industry summaries: SecurityScorecard, Bitsight, Compyl, BitLyft, ConnectWise, Huntress, USCSI (2025–2026)

---

*Orientation and assessment aid only — not legal advice or a certification guarantee. Verify current control text with the issuing authority and qualified counsel.*

*Companion document: [`security_implementation.md`](security_implementation.md) — how AutoAnalyzer can expose these as multi-select scan/test preconfigurations.*
