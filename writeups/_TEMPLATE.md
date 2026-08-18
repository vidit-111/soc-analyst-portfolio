# <Investigation Title>

**Environment:** <e.g. TryHackMe SOC Simulator>  ·  **Difficulty:** <Easy / Medium / Hard>  ·  **Date completed:** <YYYY-MM-DD>
**Tags:** `phishing` `threat-actor` `splunk` `mitre-attack` `dfir`

> Educational lab exercise. Specific answer values are redacted/masked in line with the platform's terms — this write-up focuses on methodology.

---

## Scenario & objective
<2–4 sentences: what the scenario simulated and what you were asked to do. Set the context a reader needs, no more.>

## Environment & data sources
<What you had to work with: SIEM, log sources (Sysmon, Windows Security, network/DNS logs), analyst VM, threat-intel platform, etc.>

## Tools used
<Bullet the tools and what you used each for.>

## Investigation & methodology
<The core section. Walk through HOW you approached it — what you pivoted on, what queries/filters you used (conceptually), how you separated signal from noise, how you built the timeline. This is the part hiring managers read closely. Show reasoning, not just results.>

## Key findings
<What the investigation established: the attack chain, the disposition (true/false positive), the business impact. Keep specific gradeable answer-values redacted or masked.>

## Indicators of compromise (IOCs)
<A short table. Mask answer-specific values, e.g. `185.64.x.x (OVH)`, `<redacted>.rar`. Keep the analytical point (what type of indicator, why it mattered).>

| Type | Indicator | Notes |
|---|---|---|
| Host | `<redacted>` | e.g. suspicious download, ADS Zone.Identifier |
| Network | `xxx.xx.x.x` | e.g. C2 / staging vs. benign CDN |

## MITRE ATT&CK mapping
<Table of tactic → technique → how it manifested in this scenario.>

| Tactic | Technique | Observed as |
|---|---|---|
| Initial Access | T1566 Phishing | ... |

## Remediation & recommendations
<Containment and longer-term actions you'd recommend, as you would in a real case report.>

## Lessons learned
<2–3 honest takeaways — what the scenario reinforced, what you'd do differently, a technique you got sharper on.>
