# PHP2Shell Attack Analysis
## Lab 1 | CTI Evidence, MITRE ATT&CK Mapping, and SOC Investigation

**Course:** AI-Enhanced Cybersecurity (HIT)<br>
**Group Members:** Elizabetha Afonin<br>
**Submission Date:** 28 October 2026<br>
**Last Reviewed:** 29 October 2026<br>

---

## 1. Selected CTI Report

* **Primary CTI Source:** Adel Karimi (0x4D31). *“PHP2Shell exploitation observed: packet-to-process RCE evidence.”* Published in the public `honeypot-data` repository, 24 October 2026. Accessed 28 October 2026. [[1]](#7-references)
* **Direct Report URL:** [https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md](https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md)
* **Vulnerability context:** Official PHP security advisory [[8]](#7-references) and Unit 42 [[7]](#7-references). Unit 42 retracted its earlier attribution of observed initial access to PHP2Shell on 25 October; it is not independent confirmation of exploitation of these CVEs.

> [!NOTE]
> **Scope & Methodological Boundary:**<br>
> This report analyzes published observational data from instrumented honeypots, with vulnerability context from [[7–8]](#7-references). It does not claim that our group executed the exploit or independently validated the underlying raw packet captures. All MITRE ATT&CK classifications, confidence ratings, and proposed SOC operational workflows represent our own analytical evaluation.

---

## 2. Attack Summary

The selected report documents PHP2Shell activity against instrumented PHP honeypots observed on 24 October 2026. The vulnerable targets ran PHP 8.4.26 with Apache `mod_php`. Incoming HTTP requests triggered memory pressure and disclosure, followed by an execution request that resulted in remote shell invocation. The author links the observed exploitation chain to **CVE-2026-109618**; a separate CVE-2026-109619 exploitation path was not established.

Runtime process evidence demonstrates an Apache worker process spawning `/bin/sh`, which was subsequently followed by host and identity discovery queries (`id`, `hostname`, `uname`). Outbound HTTP connection attempts were also logged. While these observations firmly substantiate initial access, execution, and local discovery, they do not demonstrate an established, persistent command-and-control (C2) channel or the compromise of an enterprise production environment. [[1]](#7-references)

The primary analytical objective for this laboratory is to map each empirically supported behavior to MITRE ATT&CK and determine the exact telemetry a Security Operations Center (SOC) requires before escalating an incident. We treat achieving remote code execution (RCE) as the verified outcome, while the adversary's ultimate objectives remain undetermined.

---

### Vulnerability and Remediation

CVE-2026-109618 is a PHP memory-handling flaw: an out-of-memory error can interrupt request processing while internal state is incomplete, and request cleanup may then use that invalid state. Apache `mod_php` can reach this path before application code runs. The official PHP advisory confirms unauthenticated RCE as the web worker account, not automatic root access, and rates the vulnerability CVSS v4.0 9.2 (Critical). The affected lab target used PHP 8.4.26; the first fixed release in that branch is 8.4.27. Other fixed branch releases are 8.2.35, 8.3.36, and 8.5.12; install an applicable patched release or vendor backport and restart PHP workers. [[8]](#7-references)

## 3. Attack Flow

### Sequence Recorded in the Source

The following paraphrases the source report's “Four request stages on the wire” in the same order; it is a published observation, not an experiment performed for this submission. [[1]](#7-references)

1. **A1 — Memory pressure:** an HTTP multipart request exhausted PHP's request memory limit.
2. **B1 — Disclosure:** a subsequent response exposed memory through an abnormally large session cookie.
3. **A2 — Further memory pressure:** another request caused a further out-of-memory condition.
4. **B2 — Execution:** a target-adjusted request was correlated with Apache spawning `/bin/sh`.

Subsequent commands queried identity and host information and attempted outbound callbacks. The source correlates 35 execution-stage requests with 35 Apache-parent shell starts across three targets. These process records establish execution; HTTP response codes or worker crashes alone do not. [[1]](#7-references)

### ATT&CK Overview

```mermaid
flowchart LR
    A["Exploit web application<br/><code>Initial Access · T1190</code>"] --> B["Run Unix shell<br/><code>Execution · T1059.004</code>"]
    B --> C["Query user and system<br/><code>Discovery · T1033 / T1082</code>"]
    C --> D["Attempt outbound communication<br/><code>C2 purpose unresolved · see Section 6</code>"]
```

![Figure 1: Attack Flow Diagram](attack_flow.png)
*Figure 1. Analytical sequence based on honeypot case evidence [1]. Memory pressure and disclosure form the exploit stage. The final outbound branch represents an unconfirmed attempt rather than an established C2 channel.*

---

## 4. Evidence-Based MITRE ATT&CK Mapping

Four observable behaviors substantiated by empirical telemetry in the report are classified below. Evidence pointers refer to specific sections in [[1]](#7-references); definitions and tactic assignments align with official MITRE ATT&CK standards [[2–5]](#7-references).

| Observed Behavior | ATT&CK Tactic | Technique & ID | Evidence and Mapping Rationale | SOC Telemetry & Investigation |
| :--- | :--- | :--- | :--- | :--- |
| **HTTP exploitation** | Initial Access | **Exploit Public-Facing Application**<br>[`T1190`](https://attack.mitre.org/techniques/T1190/) | **Evidence:** [1], *“Case evidence: HTTP request to Apache child process.”* Exploiting a network-exposed service to gain initial code execution directly satisfies T1190 [2]. **Confidence: High**. *Constraint:* Does not establish access beyond the targeted container/host. | Correlate incoming HTTP requests with PHP core memory errors and spawned child processes. Inspect web server version, loaded modules, and patch baseline. |
| **`/bin/sh` execution** | Execution | **Command and Scripting Interpreter: Unix Shell**<br>[`T1059.004`](https://attack.mitre.org/techniques/T1059/004/) | **Evidence:** [1], *“Selected runtime records.”* A standard Unix command interpreter was invoked directly by the web server daemon [3]. **Confidence: High**. *Constraint:* A shell was spawned by the server worker; this does not prove an on-disk web shell file. | Inspect full process tree, parent PID (`apache2`), command line arguments, execution context (UID 33 / `www-data`), and child spawns. Preserve memory and process timeline. |
| **`id` / `id -un`** | Discovery | **System Owner/User Discovery**<br>[`T1033`](https://attack.mitre.org/techniques/T1033/) | **Evidence:** [1], *“Selected runtime records,”* identity query entries immediately following shell spawn. Querying system identity to determine execution context satisfies T1033 [4]. **Confidence: High**. *Constraint:* Benign in administrative contexts; suspicious due to process ancestry. | Review executing UID and arguments. Correlate with the exploit-spawned shell to determine whether the adversary escalated beyond low-privileged service account limits. |
| **`hostname` / `uname -m`** | Discovery | **System Information Discovery**<br>[`T1082`](https://attack.mitre.org/techniques/T1082/) | **Evidence:** [1], *“Selected runtime records,”* host and kernel architecture queries. Enumerating OS and hardware architecture satisfies T1082 [5]. **Confidence: High**. *Constraint:* Local reconnaissance only; does not prove network scanning. | Examine execution logs and captured command standard output. Determine whether collected system information remained local or was transmitted outbound. |

> [!IMPORTANT]
> **Mapping Discipline:**<br>
> ATT&CK techniques identify observable adversary behaviors. They do not constitute proof of identity, malicious intent, persistence, or secondary lateral compromise. T1190, T1033, and T1082 have no sub-techniques in the consulted ATT&CK entries; T1059.004 is the specific Unix Shell sub-technique supported by the process evidence.

---

## 5. Proposed SOC Investigation Workflow

The operational investigation procedure below outlines how an enterprise SOC should detect, triage, and investigate similar PHP exploitation attempts:

```mermaid
graph TD
    subgraph Tier1["Tier 1: Alert Triage & Validation"]
        T1_1["Ingest WAF / EDR Alert"] --> T1_2["Verify Parent-Child Chain:<br/><code>apache2</code> → <code>/bin/sh</code>"]
        T1_2 --> T1_3["Check Context & Service Account<br/>(Exclude scheduled maintenance)"]
        T1_3 --> T1_4["Group Correlated Events & Escalate"]
    end

    subgraph Tier2["Tier 2: Deep Investigation & Scope Analysis"]
        T2_1["Reconstruct Request-to-Worker-to-Process Chain"]
        T2_2["Analyze Downstream Activity:<br/>Discovery commands, file modifications, drops"]
        T2_3["Inspect Network Telemetry:<br/>Verify outbound SYN vs completed sessions"]
        T2_4["Evaluate Blast Radius & Formulate Containment"]
    end

    T1_4 ==> T2_1
    T2_1 --> T2_2
    T2_2 --> T2_3
    T2_3 --> T2_4
```

### A. Exploitation of Exposed Web Application (T1190)
* **Telemetry Sources:** Reverse-proxy / WAF logs, Apache access and error logs, PHP error logs, network packet captures (PCAP), and application container configuration inventories.
* **Tier 1 (Triage):** Validate the alert timestamp against reverse-proxy access logs. Check whether probes came from an authorized scanner and whether correlated process activity occurred. Verify the PHP build and vendor patch status; the observed target was PHP 8.4.26, with a fix available in 8.4.27 [8]. Do not classify a request as benign solely from its status code or missing process events; first check telemetry coverage.
* **Tier 2 (Investigation):** Reconstruct the exact relationship between incoming HTTP request payloads, worker process memory crashes, and downstream process executions. Cross-correlate IP provenance across independent logs. Query enterprise telemetry across all web assets to identify whether the same attack signature targeted other systems.

### B. Unexpected Shell Execution (T1059.004)
* **Telemetry Sources:** EDR, Linux `auditd`, or Tetragon (eBPF) process execution telemetry containing executable paths, parent PIDs, UID/GID, full command line strings, container namespaces, and exit codes.
* **Tier 1 (Triage):** Inspect the complete process hierarchy. Confirm whether `apache2` or `php-fpm` legitimately spawns `/bin/sh` in the environment and compare with the application’s expected subprocess behavior. Do not close alerts merely because the process executed as a low-privileged user (`www-data`).
* **Tier 2 (Investigation):** Trace all descendant processes spawned by `/bin/sh`. Check for created temporary files or dropped payloads in `/tmp`, `/dev/shm`, or web directories. Coordinate containment actions (e.g., container isolation, web service restart) with the incident commander while preserving volatile memory.

### C. System and User Discovery (T1033 & T1082)
* **Telemetry Sources:** Process execution streams, shell history, standard output capture (where EDR/eBPF supports it), and correlated network socket events.
* **Tier 1 (Triage):** Group discovery commands (`id`, `hostname`, `uname`) executing within seconds of the shell spawn into a single consolidated incident. Verify that these were not invoked by standard administrative cron jobs.
* **Tier 2 (Investigation):** Evaluate whether discovery command outputs were piped into files or outbound network streams. Distinguish passive local reconnaissance from active privilege escalation attempts.

### Evidence Handling and Decision Record
* Preserve raw log records with verified UTC timestamps.
* Hash exported evidence files (SHA-256) to check integrity; record collection time, collector, storage, and transfers to document chain of custody.
* Clearly delineate confirmed facts from working hypotheses in ticket documentation.

---

## 6. Uncertain Mapping and Alternative Interpretation

### Candidate: Command and Control via Web Protocols (`T1071.001`)

* **Unresolved Analytical Question:** Does the observed outbound HTTP connection attempt warrant mapping to **T1071.001 (Application Layer Protocol: Web Protocols)** under the **Command and Control** tactic? [[6]](#7-references)
* **Why it was withheld:** An attempted HTTP connection alone does not establish successful communication or a command-and-control purpose. T1071.001 describes use of web protocols for C2; a persistent or interactive session is not a universal prerequisite [6].
* **Alternative Explanations:**
  1. *Execution-verification callback (Canary):* The adversary may have executed a single non-interactive request (e.g., via `curl`) simply to confirm external reachability or notify a webhook that exploitation succeeded.
  2. *Failed egress connection:* Honeypot telemetry indicates that network egress was restricted (e.g., `TCP_SYN_SENT` without response), so successful data exchange or payload staging is not established for those recorded attempts.

### Evidence Required to Resolve

To conclusively map this behavior to T1071.001 or confirm an alternative hypothesis, a SOC analyst should seek:
1. **Full application-layer packet capture (PCAP) or TLS proxy logs:** Capturing completed HTTP request and response headers/bodies to verify whether commands, tasking instructions, or payloads were exchanged.
2. **Endpoint process-socket correlation:** Confirming that the outbound network socket was owned by the spawned shell or a known secondary payload.
3. **Subsequent interactive activity:** Observing subsequent commands executed as a direct result of incoming server responses.

### Review Question and Analytical Conclusion

What evidence distinguishes an exploit-verification callback from traffic used for command and control?

The published observations support attempted callbacks but do not establish their use for C2. T1071.001 therefore remains a candidate rather than a confirmed mapping. Payload contents, process context, or evidence of tasking could resolve its purpose; periodic traffic alone would not. This is the author's analytical conclusion; no instructor or peer review is claimed.

## Insights / What I Learned

I learned to separate a vulnerable configuration, an exploitation attempt, and confirmed execution by correlating HTTP evidence with process events. ATT&CK mapping should describe supported behavior while keeping uncertain interpretations, such as the purpose of an outbound callback, explicit. For SOC investigation, request, process, and network records together are more informative than a single alert or HTTP status code.

---

## 7. References

* **[1]** Karimi, A. (0x4D31). *PHP2Shell exploitation observed: packet-to-process RCE evidence*. Public honeypot-data repository (24 Oct 2026). [GitHub Report Link](https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md)
* **[2]** MITRE ATT&CK. *T1190 — Exploit Public-Facing Application*. [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)
* **[3]** MITRE ATT&CK. *T1059.004 — Command and Scripting Interpreter: Unix Shell*. [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)
* **[4]** MITRE ATT&CK. *T1033 — System Owner/User Discovery*. [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)
* **[5]** MITRE ATT&CK. *T1082 — System Information Discovery*. [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)
* **[6]** MITRE ATT&CK. *T1071.001 — Application Layer Protocol: Web Protocols*. [https://attack.mitre.org/techniques/T1071/001/](https://attack.mitre.org/techniques/T1071/001/)
* **[7]** Palo Alto Networks Unit 42. *Threat Brief: Critical Vulnerabilities in PHP (CVE-2026-109618, CVE-2026-109619)* (23–25 Oct 2026). [https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/)
* **[8]** PHP project. *RCE via OOM corruption — GHSA-w8hw-w9fx-j79w / CVE-2026-109618* (21 Oct 2026). [Official PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
