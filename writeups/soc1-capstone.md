# SOC 1 Capstone - Multi-Stage Intrusion DFIR

**Environment:** TryHackMe SOC 1 (Capstone Challenges)  ·  **Difficulty:** Medium–Hard  ·  **Date completed:** 2025-12-10
**Tags:** `dfir` `memory-forensics` `network-forensics` `email-analysis` `powershell` `mitre-attack`

> Educational lab exercises carried out in the TryHackMe SOC 1 capstone. Organisations, hosts, and users are fictional scenario content. Flag values and other gradeable answer strings (exact IPs, domains, hashes, filenames) are masked or redacted in line with TryHackMe's terms — the focus is on forensic methodology and how findings are pieced together across artefacts.

---

## Overview & objective

Four post-compromise investigations, each starting from a different position in the attack and demanding a different forensic discipline. Across the set, the task was the same in spirit: take the available artefacts - endpoint logs, memory images, packet captures, email, and SIEM data — and reconstruct the full intrusion, from initial access through to the attacker's objective.

Where a real-time triage scenario tests speed, these capstones test **depth**: normalising evidence from multiple sources into a single timeline, decoding obfuscation, and following an adversary end-to-end through the traces they leave behind.

## Scenarios at a glance

| Scenario | Forensic focus | Key artefacts & tools |
|---|---|---|
| **Tempest** | Endpoint + network | Sysmon EVTX, Windows Event Logs, PCAP · EvtxECmd, Timeline Explorer, Wireshark/Brim, VirusTotal |
| **Boogeyman 1** | Email + endpoint + network | Phishing email, `.lnk`, PowerShell logs, PCAP · LNKParse3, jq, tshark, CyberChef |
| **Boogeyman 2** | Email + memory | Macro document, memory image · olevba (oletools), Volatility 3, strings |
| **Boogeyman 3** | SIEM threat hunting | Centralised logs · Elastic Stack, Kibana, KQL |

## Investigation & methodology

**Tempest — full attack chain from a single workstation.** Starting from endpoint telemetry and a packet capture, I traced the intrusion from a malicious document that exploited a client-side vulnerability (Follina / CVE-2022-30190, via MSDT) to execute code. From there: a Base64-encoded PowerShell stage, staged binary downloads confirmed in the PCAP, a SOCKS proxy set up for pivoting, privilege escalation via a PrintSpoofer-style technique, a rogue local account, and service-based persistence. EvtxECmd and Timeline Explorer normalised the event logs into a timeline; Wireshark/Brim tied the network side to it.

**Boogeyman 1 — from phishing email to credential theft.** This one began in the inbox. I analysed the email's headers and delivery path, then parsed a malicious `.lnk` shortcut to recover the embedded command, decoded the Base64 PowerShell payload, and followed the chain through to DNS-based exfiltration and theft from a password manager. jq was useful here for querying JSON-formatted PowerShell operational logs; tshark and CyberChef handled the network and decoding work.

**Boogeyman 2 — macro document and memory forensics.** A macro-enabled document arrived disguised as a résumé. olevba extracted and de-obfuscated the VBA macro; from there the chain ran through a LOLBin (`wscript`) that pulled a second-stage payload, with scheduled-task persistence. The distinguishing skill here was **memory forensics**: using Volatility 3 against a memory image to recover running processes, network connections, and command-line artefacts that confirmed the C2 and tied the stages together.

**Boogeyman 3 — hunting the chain in a SIEM.** The final scenario shifted from single-host forensics to **threat hunting at scale** in Elastic/Kibana with KQL. The intrusion ran from a phishing lure through HTA execution (`mshta.exe`), an implant copied onto the host, lateral movement, and ultimately domain controller compromise. The work was about pivoting efficiently through large log volumes — from one indicator to the next — to reconstruct a chain no single event revealed on its own.

## Cross-cutting skills demonstrated

- **Multi-source correlation:** normalising endpoint, memory, network, email, and SIEM evidence into a single coherent timeline.
- **Obfuscation handling:** decoding Base64/encoded PowerShell and de-obfuscating macros as routine steps.
- **Adversary technique recognition:** identifying LOLBin abuse, privilege escalation, and multiple persistence mechanisms (services, scheduled tasks, rogue accounts).
- **Tooling breadth:** applying the right tool to each artefact class rather than forcing one approach.

## Key findings

Each scenario was reconstructed end-to-end — initial access → execution → escalation/persistence → objective:

- **Tempest:** document exploit → PowerShell → pivot (SOCKS) → privilege escalation → rogue account + service persistence.
- **Boogeyman 1:** phishing → `.lnk` → PowerShell → DNS exfiltration → password-store theft.
- **Boogeyman 2:** macro document → LOLBin stage-2 download → scheduled-task persistence → C2 (confirmed in memory).
- **Boogeyman 3:** phishing → HTA/`mshta` → implant → lateral movement → domain controller compromise.

## MITRE ATT&CK mapping (consolidated)

| Tactic | Technique | Seen in |
|---|---|---|
| Initial Access | T1566 — Phishing | All four |
| Execution | T1203 — Exploitation for Client Execution (Follina) | Tempest |
| Execution | T1059.001 — PowerShell | Tempest, Boogeyman 1 |
| Execution | T1218.005 — Mshta | Boogeyman 3 |
| Defense Evasion | T1218 — System Binary Proxy Execution (LOLBins) | Boogeyman 2 |
| Privilege Escalation | T1068 — Exploitation for Privilege Escalation | Tempest |
| Persistence | T1543.003 / T1053.005 — Service / Scheduled Task | Tempest, Boogeyman 2 |
| Credential Access | T1555 — Credentials from Password Stores | Boogeyman 1 |
| Command & Control | T1090 — Proxy · T1071.004 — DNS | Tempest, Boogeyman 1 |
| Exfiltration | T1048 — Over Alternative Protocol | Boogeyman 1 |

## Lessons learned

- **The timeline is the deliverable.** The hardest part of multi-source DFIR isn't any single tool — it's normalising timestamps and formats from logs, packets, and memory into one narrative. Getting disciplined with timeline tooling paid off across all four.
- **Memory catches what disk and logs miss.** In Boogeyman 2, the memory image confirmed C2 and process lineage that weren't obvious from the document and task alone — a reminder to reach for volatile evidence, not just persistent artefacts.
- **Hunting scales differently from forensics.** Boogeyman 3 was a shift in mindset: with centralised logs the skill is efficient pivoting through volume, not exhaustive examination of one host. Both muscles matter.
- **Decoding is routine, not exceptional.** Base64 PowerShell and obfuscated macros show up constantly; treating de-obfuscation as a standard step rather than a special case kept each investigation moving.
