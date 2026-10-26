# Cyber Security Portfolio

A selection of academic projects from my **MSc Cyber Security** (University of Hertfordshire). Each project has its own write-up with methodology, findings and remediation.

All practical work was performed in isolated lab environments with authorisation. Lab-specific data (target addresses, credentials, recovered passwords and case details) has been removed from these public versions.

## Projects

| # | Project | Focus | Key tools / skills |
|---|---------|-------|--------------------|
| ⭐ | [Windows Privilege-Escalation Detection](04-privesc-detection/) — **MSc dissertation** | Python blue-team detectors for 5 privesc techniques | Python, `pywin32`, Windows internals, detection engineering |
| 2 | [Penetration Test — Linux Server](02-penetration-test/) | Grey-box network penetration test | Nmap, Metasploit, Nikto, Hydra, privilege escalation |
| 3 | [Threat Model — Fintech](01-threat-model/) | Threat modelling for a payments company | Attack trees, MITRE ATT&CK, GDPR/PCI DSS/ISO 27001 |
| 4 | [Digital Forensics — Disk Image](03-digital-forensics/) | Forensic examination of a disk image | Autopsy, registry/artefact analysis, chain of custody |

> The dissertation project contains my own Python code. The vulnerable-lab setup script it relied on is not mine (Tib3rius/Sagi Shahar's *lpeworkshop*) and is deliberately left out — see that project's README.

## Skills summary

- **Blue team:** detection engineering, Windows Event Log / registry / service monitoring, Python tooling
- **Offensive:** reconnaissance, service enumeration, vulnerability assessment, exploitation, privilege escalation
- **Defensive:** threat modelling, security architecture, remediation planning, compliance (GDPR, PCI DSS, ISO 27001)
- **Forensics:** evidence acquisition and integrity, Windows artefact analysis, timeline reconstruction, reporting
- **Tools:** Kali Linux, Nmap, Metasploit, Nikto, Hydra, Autopsy, Python, pywin32
