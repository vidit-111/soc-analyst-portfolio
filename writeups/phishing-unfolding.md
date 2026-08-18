# Phishing Unfolding - Real-Time SOC Triage

**Environment:** TryHackMe SOC Simulator  ·  **Difficulty:** Medium  ·  **Date completed:** [add your date, YYYY-MM-DD]
**Tags:** `phishing` `alert-triage` `splunk` `dns-exfiltration` `case-reporting` `mitre-attack`

> Educational lab exercise carried out in the TryHackMe SOC Simulator. The organisation, hosts, and users are fictional scenario content. Specific gradeable answer values (exact indicator strings, addresses, filenames) are masked or redacted in line with TryHackMe's terms — the focus of this write-up is the real-time triage workflow and reporting approach.

---

## Scenario & objective

A phishing-driven intrusion unfolding in real time. Acting as the on-shift SOC analyst, the task was to work a live alert queue as detections arrived, prioritise by severity and timestamp, disposition each alert as a true or false positive, investigate the genuine detections in the SIEM, and document a structured case report for each — all while the attack progressed from initial delivery through to data exfiltration.

Unlike a retrospective investigation, this scenario tested **operational triage under time pressure**: keeping the queue moving, not over-escalating noise, and producing clear, defensible case notes at pace.

## Environment & data sources

- **SIEM:** Splunk (selected for search and correlation across the incoming alert stream)
- **Alert queue / case management:** incident portal for taking ownership, dispositioning, and writing per-alert reports
- **Log sources:** email/gateway telemetry, endpoint process and command-line events, and network/DNS query logs
- **Supporting tooling:** analyst workstation and reputation/threat-intel lookups for artefact context

## Tools used

- **Splunk** — primary investigation: querying and pivoting across email, endpoint, and DNS events to confirm or dismiss each alert
- **Alert queue / IRP** — prioritisation, ownership, dispositioning, and case documentation
- **Reputation / threat-intel lookups** — validating domains and artefacts encountered during triage

## Investigation & methodology

**1. Work the queue by priority, not by order of arrival.** As alerts populated in real time, I triaged by severity and timestamp rather than first-in-first-out — surfacing the highest-impact detections first so the genuine intrusion activity got attention ahead of low-severity noise.

**2. Disposition before deep-diving.** Each alert was first classified true or false positive. Confidently dismissing benign detections is what keeps a live queue moving; sinking investigation time into every alert equally is how a real SOC falls behind. Every alert I closed carried a documented reason for its disposition.

**3. Reconstruct the chain across data sources.** For the true positives, I pivoted across log sources in Splunk to connect what were, at the alert level, separate events into a single coherent intrusion:

- **Initial access** — a phishing email delivered the lure that began the intrusion.
- **Execution** — a malicious PowerShell script executed on the endpoint, establishing a **PowerCat reverse shell** back to attacker infrastructure.
- **Discovery** — hands-on-keyboard recon followed (system and user enumeration via built-in commands).
- **Collection** — files of interest were staged into a hidden directory and archived for exfiltration.
- **Exfiltration** — data was tunnelled out over **DNS**, using encoded lookups (`nslookup`-style queries paired with the PowerShell process) to smuggle information past controls that watch HTTP but not DNS.

**4. Escalate on business impact.** The DNS-exfiltration alert was the pivotal one: recognising `nslookup.exe` driven by `powershell.exe` as covert exfiltration — rather than benign name resolution — is what justified escalation, given the high impact of a data breach. The case report for that alert set out the technique, the affected entities, the timeline, and the reasoning for escalation.

**5. Document to a consistent standard.** Each case report followed a 5 Ws structure — who/what was affected, what happened, where, when, and why it mattered — with escalation rationale, recommended remediation, and a list of attack indicators.

## Key findings

- **Full attack chain identified:** phishing email → malicious PowerShell (PowerCat reverse shell) → system/user discovery → data staged and archived → **DNS-tunnelled exfiltration**.
- **DNS exfiltration correctly recognised:** the pairing of `nslookup` with the PowerShell process was dispositioned as covert data exfiltration, not benign traffic, and escalated on business-impact grounds.
- **Triage performance (scenario-scored):**
  - **True-positive identification rate: 100%** — every malicious detection correctly caught.
  - **Mean time to resolve: 6 minutes** — alerts worked and closed efficiently under live conditions.
  - **Alerts closed: 29.**

## Indicators of compromise (IOCs)

*Answer-specific values masked in line with platform terms; technique-level detail retained to show the analytical point.*

| Type | Indicator | Notes |
|---|---|---|
| Host | `<malicious>.ps1` (PowerShell) | Downloaded/executed script establishing the reverse shell |
| Process | `powershell.exe` → `nslookup.exe` | Parent/child pairing driving DNS-based exfiltration |
| Host | `%TEMP%\<hidden-dir>\<archive>.zip` | Staged, archived data prepared for exfiltration |
| Network | `<encoded-subdomain>.<attacker-domain>` | Encoded DNS lookups used as the exfiltration channel |

## MITRE ATT&CK mapping

| Tactic | Technique | Observed as |
|---|---|---|
| Initial Access | T1566 — Phishing | Lure delivered by email to begin the intrusion |
| Execution | T1059.001 — PowerShell | Malicious script run on the endpoint |
| Command & Control | T1071.004 — Application Layer Protocol: DNS | Covert channel over DNS |
| Discovery | T1082 / T1033 — System & Owner/User Discovery | Built-in recon commands |
| Collection | T1560 — Archive Collected Data | Files staged and zipped |
| Exfiltration | T1048 — Exfiltration Over Alternative Protocol | Data smuggled out via DNS queries |

## Remediation & recommendations

- **Immediate:** isolate the affected host; kill the PowerShell/reverse-shell process; block the attacker domain at the DNS resolver and gateway.
- **Containment:** reset credentials for the compromised user; hunt for the same PowerShell/`nslookup` pattern across other hosts.
- **Preventive:** alert on `powershell.exe` spawning `nslookup.exe`; baseline and monitor DNS query volume/length to catch tunnelling; strengthen email-gateway filtering and run targeted user-awareness follow-up.

## Lessons learned

- **Dispositioning is a skill in its own right.** The metric that mattered most wasn't catching the true positives (I caught them all) but doing it *at pace* — a 6-minute MTTR came from confidently closing alerts rather than over-investigating each one.
- **DNS is a blind spot worth watching.** Exfiltration over DNS slips past controls focused on web traffic; the `powershell.exe` → `nslookup.exe` pattern is a high-value detection to carry forward.
- **Honest growth area:** my false-positive discipline was solid but not perfect this run — a few benign alerts were escalated more cautiously than needed. Tightening that (dismissing benign detections faster and more decisively) is the specific thing I'd sharpen next, and it's a better use of shift time than re-checking true positives I've already confirmed.
- **Reporting consistency compounds.** Feedback on my case notes flagged that the "where" of an incident could be stated more explicitly and consistently — a small habit that makes every report faster to action for the next analyst in the chain.
