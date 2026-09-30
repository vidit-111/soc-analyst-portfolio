# NerisBot - Splunk C2 Threat Hunt

**Environment:** CyberDefenders (Blue Team CTF) | **Category:** Threat Hunting / Network Forensics | **Date completed:** [2026-09-29]
**Tags:** `threat-hunting` `splunk` `c2` `network-forensics` `suricata` `zeek` `mitre-attack`

> Educational lab exercise from CyberDefenders. Challenge-specific answer values (IPs, domains, file hashes) are redacted or masked in line with the platform's terms. The SPL below is the actual search chain used, with answer values masked - the focus is the hunt methodology, not the solutions.

---

## Scenario & objective

Unusual network activity was detected in a university environment, with anomalies from the previous six hours suggesting command-and-control (C2) communication and a possible external compromise. The task was to hunt the network logs in Splunk to establish the scope of the activity and identify the C2 infrastructure and the compromised host.

This was a SIEM-driven hunt: the evidence was already indexed in Splunk as Suricata IDS and Zeek logs, so the work was pivoting across those sources with SPL to turn an initial signal into a verified set of IOCs.

## Environment & data sources

- **SIEM:** Splunk, with the network logs pre-ingested
- **Log sources:** Suricata IDS/HTTP events, and Zeek `dns` and `files` logs
- **Enrichment:** VirusTotal for hash reputation

## Tools used

- **Splunk (SPL)** - `metadata`, `stats`, `table`, `dedup`, and targeted filtering across sourcetypes
- **VirusTotal** - confirming maliciousness of downloaded files by hash

## Investigation & methodology

The hunt moved from enumerating the available logs, to isolating the external IP behind the downloads, to resolving its C2 infrastructure, and finally to enumerating and verifying the files it delivered. SPL below is the actual search chain, with answer-specific values masked.

**1. Enumerate the data first.**
```
| metadata type=sourcetypes | dedup sourcetype | table sourcetype
```
Listed the available sourcetypes and confirmed the ones worth pivoting across: `suricata`, `zeek:dns`, and `zeek:files`.

**2. Find the external IP behind the downloads.** Since the concern was a downloaded executable, I pivoted on Suricata HTTP events and aggregated by destination:
```
sourcetype="suricata" event_type="http"
| stats values(http.http_user_agent) as user_agents, values(http.url) as urls, values(src_ip) as server by dest_ip
```
One external IP stood out - multiple executable downloads paired with a conspicuously outdated user-agent (a legacy MSIE 6.0 string), which is itself a red flag in a modern environment. Narrowing to executables confirmed it:
```
sourcetype="suricata" event_type="http" AND http.url="*.exe"
| stats values(http.http_user_agent) as user_agents, values(http.url) as urls, values(src_ip) as server by dest_ip
```
Three IPs served `.exe` files, but only the flagged one carried the anomalous user-agent - the attacker IP (`<attacker-ip>`).

**3. Resolve the C2 domain.** Pivoted into Zeek DNS for that IP:
```
sourcetype="zeek:dns" AND "<attacker-ip>"
```
This surfaced repeated resolution of the C2 domain (`<c2-domain>`) and, usefully, exposed the internal host generating those lookups.

**4. Identify the compromised host.** In the same DNS records, the internal IP appearing as `id_orig_h` - the originator of the queries and the recipient of the downloads - was the targeted system (`<victim-ip>`).

**5. Enumerate and verify the downloaded files.** Pulled the unique files delivered by the suspicious hosts from the Zeek files log:
```
sourcetype="zeek:files" AND tx_hosts IN ("<ip1>", "<ip2>", "<ip3>")
| table filename, md5
| dedup md5
```
This returned several unique files by MD5. Running the hashes through VirusTotal confirmed the majority as malicious, turning raw downloads into verified IOCs.

**6. Unmask the file disguised as text.** One download claimed to be a `.txt` but was far too large (~37 KB) for plain text. Spotted it in the Suricata HTTP GET traffic, then cross-referenced the Zeek files log by byte size to pin the exact file and its hash:
```
sourcetype="suricata" event_type="http" http.http_method="GET"
| stats values(http.url) as urls, values(src_ip) as server by dest_ip
```
```
index=* sourcetype="zeek:files" tx_hosts="<attacker-ip>" seen_bytes=<size>
```
The size mismatch - a "text" file the size of a small executable - was the tell; the file's SHA256 (`<sha256>`) confirmed it.

## Key findings

- **Origin:** an external IP (`<attacker-ip>`) delivering executables over HTTP, flagged by an anomalous legacy MSIE 6.0 user-agent
- **C2:** a control domain (`<c2-domain>`) confirmed by repeated Zeek DNS resolution
- **Compromised host:** an internal university system (`<victim-ip>`) that made the C2 lookups and received the downloads
- **Payloads:** several unique files delivered, the majority verified malicious via VirusTotal
- **Evasion:** one payload disguised as a `.txt` file, exposed by a claimed-type vs actual-size mismatch

## Indicators of compromise (IOCs)

*Answer-specific values masked in line with platform terms.*

| Type | Indicator | Notes |
|---|---|---|
| Network | `<attacker-ip>` | External origin; anomalous MSIE 6.0 UA; served `.exe` payloads |
| Network | `<c2-domain>` | C2 domain, repeated Zeek DNS resolution |
| Host | `<victim-ip>` | Compromised university host |
| File | `<sha256>` (payload disguised as `.txt`) | Verified malicious; size-mismatch tell |
| File | multiple MD5s | Unique downloads, majority VirusTotal-flagged |

## MITRE ATT&CK mapping

| Tactic | Technique | Observed as |
|---|---|---|
| Command & Control | T1071.001 - Web Protocols | HTTP delivery / C2 |
| Command & Control | T1071.004 - DNS | Resolution of C2 domain |
| Command & Control | T1105 - Ingress Tool Transfer | Executables pulled to the host |
| Defense Evasion | T1036 - Masquerading | Payload disguised as a `.txt` file |

## Remediation & recommendations

- **Immediate:** isolate the compromised host; block the attacker IP and C2 domain at the firewall and DNS resolver; remove the downloaded payloads
- **Containment:** hunt the file hashes and C2 indicators across the estate for other infected hosts; rotate credentials used on the affected system
- **Preventive:** alert on outdated/rare user-agents and on file downloads whose content type conflicts with their size; enrich Suricata/Zeek data with threat-intel and VirusTotal lookups so known-bad hashes and domains fire automatically

## Lessons learned

- **Enumerate sourcetypes first.** Knowing up front that `suricata`, `zeek:dns`, and `zeek:files` were all available shaped every pivot that followed instead of guessing at fields mid-hunt.
- **Anomalous user-agents are cheap wins.** A decade-old MSIE 6.0 string among modern traffic flagged the malicious host almost immediately - worth baselining and alerting on.
- **Claimed type versus actual size catches disguises.** A "txt" file at ~37 KB was the giveaway; file metadata beats filenames every time.
- **Enrichment turns suspicion into evidence.** Deduping by hash and checking VirusTotal converted a list of downloads into confirmed malicious IOCs I could stand behind.
- **Correlation is the whole game.** HTTP gave the downloads, DNS gave the C2 domain and the victim, and the files log gave the hashes. No single source told the story - tying them together in Splunk did.
