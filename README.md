# Cybersecurity Labs

**Institution:** Holon Institute of Technology (HIT) — School of Computer Science  
**Course:** Introduction to AI-Based Cybersecurity | Fall 2026  
**Instructors:** Dr. Andrei Kojukhov, Mr. Viacheslav Nefedov  
**Student:** Elizabetha Afonin ([@lizaafo](https://github.com/lizaafo))  

---

## Repository Overview

This repository contains laboratory assignments, cyber threat intelligence (CTI) research, and Security Operations Center (SOC) investigation workflows completed for the Introduction to AI-Based Cybersecurity course.

---

## Laboratory Deliverables

### [Lab 1: From CTI to SOC Investigation and MITRE ATT&CK Mapping](labs/lab1/)

* **Topic:** Empirical analysis of honeypot exploitation telemetry (**PHP2Shell / CVE-2026-109618**).
* **Deliverables:**
  * **[`lab1.md`](labs/lab1/lab1.md)** — Reviewed laboratory submission in the required Markdown format.
  * **[`README.md`](labs/lab1/README.md)** — Laboratory entry page and link to the submission.
  * **[`attack_flow.png`](labs/lab1/attack_flow.png)** — Attack sequence diagram.
* **Key MITRE ATT&CK Techniques Mapped:**
  * Initial Access: Exploit Public-Facing Application (`T1190`)
  * Execution: Command and Scripting Interpreter: Unix Shell (`T1059.004`)
  * Discovery: System Owner/User Discovery (`T1033`)
  * Discovery: System Information Discovery (`T1082`)
  * Candidate Technique Evaluated: Web Protocols (`T1071.001`)
