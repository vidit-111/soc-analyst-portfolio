# APT28: Link to Trouble - SOC Investigation

**Environment:** TryHackMe SOC Simulator  ·  **Difficulty:** Hard  ·  **Date completed:** 2025-03-12
**Tags:** `threat-actor` `apt28` `splunk` `log-correlation` `mitre-attack` `case-reporting`

> Educational lab exercise carried out in the TryHackMe SOC Simulator. The victim organisation, hosts, and users are fictional scenario content. Specific gradeable answer values (exact indicator strings, addresses) are masked or redacted in line with TryHackMe's terms - the focus of this write-up is the investigative methodology and reporting approach.

---

## Scenario & objective

The simulated organisation had been repeatedly targeted by **APT28 (Fancy Bear)**, a nation-state threat actor. Acting as the SOC analyst, the task was to triage the incoming alert queue and investigate a suspected intrusion, tracing adversary activity across the full attack lifecycle — from initial access through execution, persistence, privilege escalation, credential access, and network discovery — by correlating log sources in the SIEM and documenting each stage in analyst case reports.

## Environment & data sources

- **SIEM:** Splunk (chosen for log search and correlation)
- **Log sources:** endpoint process/telemetry (Sysmon-style), Windows Security events, file/registry events, and network connection logs
- **Supporting tooling:** integrated threat-intelligence reference for APT28 TTPs; sandbox/reputation lookups for downloaded artefacts

## Tools used

- **Splunk** — primary investigation: searching, filtering, and correlating events across hosts and time
- **Threat-intelligence reference** — validating whether observed behaviours were consistent with known APT28 tradecraft
- **Reputation/lookup services** — separating benign infrastructure (CDN, ad/analytics) from suspicious destinations

## Investigation & methodology

**1. Establish the entry point.** Working the alert queue by severity and timestamp, the earliest suspicious activity centred on a user workstation where a browser process wrote an archive file to the Downloads directory. Rather than treating the download in isolation, I pivoted on the process and the file to build context around it.

**2. Confirm origin, not just presence.** The downloaded archive carried a `Zone.Identifier` Alternate Data Stream — evidence the file originated from the internet rather than being created locally. This is the kind of detail that turns "a file exists" into "a file was pulled from an external source," which materially changes the disposition.

**3. Separate signal from noise.** The browser process had generated a spread of outbound HTTPS connections around the same time. Reputation and provider lookups showed most of these resolving to CDN and analytics infrastructure (major cloud/CDN providers) — benign traffic incidental to normal browsing and the download itself. Deliberately *ruling these out* was as important as flagging the archive: over-escalating benign CDN traffic is a common triage error, and distinguishing it here kept the case focused on the genuine indicator.

**4. Trace the chain forward.** From the foothold, I followed the activity across subsequent stages — execution of a downloaded payload, a persistence mechanism registered on the host, privilege escalation, and follow-on discovery/credential-access behaviour — correlating each step across process, registry, and network events to reconstruct a coherent timeline rather than a set of isolated alerts.

**5. Attribute cautiously.** The lure pattern (an archive masquerading as a routine technical/configuration document) and the staged intrusion behaviour were **consistent with APT28-style tradecraft** against government and enterprise targets. I framed the attribution as consistent-with rather than definitive, anchoring it to what was actually observed in the logs rather than to broad claims about the group.

## Key findings

- **Initial access:** a user downloaded a `.rar` archive disguised as a technical configuration guide via the browser; the `Zone.Identifier` ADS confirmed external origin.
- **Disposition:** **true positive** — escalated. The archive represented a credible initial-foothold vector in a targeted-intrusion context, despite surrounding benign CDN traffic.
- **Attack chain:** initial access → execution of a downloaded payload → persistence on the host → privilege escalation → discovery / credential access, reconstructed by correlating endpoint, registry, and network events across the SIEM.
- **Noise correctly excluded:** multiple benign HTTPS connections to CDN/analytics providers were identified and dispositioned as non-malicious.

## Indicators of compromise (IOCs)

*Answer-specific values masked in line with platform terms; provider attribution retained to show the analytical distinction.*

| Type | Indicator | Notes |
|---|---|---|
| Host | `<config-guide-lure>.rar` (Downloads) | Archive masquerading as a technical document; primary initial-access artefact |
| Host | `...\<file>.rar:Zone.Identifier` | ADS confirming internet origin |
| Network | `xx.xx.xx.xx` (major CDN) | Benign — incidental HTTPS traffic, dispositioned as non-malicious |
| Network | `xxx.xx.xxx.xxx` (hosting provider) | Reviewed against download activity during triage |

## MITRE ATT&CK mapping

| Tactic | Technique | Observed as |
|---|---|---|
| Initial Access | T1566 — Phishing | Archive lure delivered and downloaded via browser |
| Execution | T1204 — User Execution | User-initiated handling of the downloaded archive/payload |
| Persistence | T1547 — Boot/Logon Autostart Execution | Autostart entry registered on the host |
| Privilege Escalation | (host-based escalation) | Escalation activity following the foothold |
| Discovery / Credential Access | T1087 / T1003-class | Follow-on enumeration and credential-focused activity |

*(Techniques listed at the tactic level; exact sub-technique IDs generalised to keep this a methodology reference rather than a solution key.)*

## Remediation & recommendations

- **Immediate:** isolate the affected host; quarantine the archive; hunt for extraction/child-process activity spawned from it.
- **Containment:** review and remove the persistence entry; rotate credentials for any accounts exposed during the credential-access stage.
- **Preventive:** block/inspect archive downloads at the web/email gateway; add detection for `Zone.Identifier`-flagged archives executing shortly after download; user-awareness follow-up for the targeted individual.

## Lessons learned

- **Ruling things out is analysis too.** The hardest and most valuable part of this triage was confidently dispositioning benign CDN traffic away from the real indicator — precision matters as much as detection.
- **Origin evidence changes dispositions.** The `Zone.Identifier` ADS was a small artefact that carried a lot of weight; low-level details often decide a case.
- **Attribute to the evidence.** It's tempting to lean on a threat group's reputation; the stronger report anchors attribution to observed behaviour and labels it "consistent with," leaving room for the investigation to speak for itself.
