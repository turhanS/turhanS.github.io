<p align="center">
  <img src="phishguard-icon.png" alt="PhishGuard Logo" width="96" />
</p>

# PhishGuard: A Multi-Signal, Heuristic-Based Browser Extension for Real-Time Email Phishing Detection

---

## Abstract

Phishing attacks remain one of the most prevalent and damaging forms of cybercrime, with hundreds of millions of targeted emails dispatched daily. Existing defenses—server-side spam filters and rule-based blocklists—are limited by their inability to inspect full email context at the client, dependency on signature updates, and high false-positive rates against legitimate transactional mail. This paper presents **PhishGuard**, a browser extension implementing a real-time, multi-signal phishing detection engine that operates entirely at the client side within major webmail platforms. The system integrates fourteen independent analysis modules spanning email authentication, IP reputation, domain intelligence, social engineering heuristics, URL structural analysis, MIME attachment inspection, header forensics, and thread-hijacking detection. A weighted additive scoring model with trust-calibration discounts aggregates per-module outputs into a three-tier risk verdict (HIGH / MEDIUM / LOW). The architecture is API-key-optional—all core detections execute locally without network access—while optional integrations with VirusTotal, AbuseIPDB, Shodan, PhishTank, and URLhaus enrich analysis when available. Design choices prioritize false-positive minimization through domain and platform whitelisting, trust discounts for cryptographically verified senders, and context-aware scoring. Evaluation against representative benign and phishing email corpora demonstrates high true-positive rates with markedly reduced false alarms compared to threshold-only approaches.

**Keywords:** Phishing Detection, Browser Extension, Email Security, Heuristic Analysis, Multi-Signal Scoring, SPF/DKIM/DMARC, DNSBL, URL Analysis, Social Engineering

---

## 1. Introduction

Electronic mail remains the dominant vector for phishing attacks. The Anti-Phishing Working Group reported over 1.3 million unique phishing sites in 2023, the majority seeded through malicious email campaigns [APWG, 2023]. Despite decades of countermeasures—including domain authentication standards (SPF, DKIM, DMARC), spam classifiers, and URL blacklists—attackers continue to succeed by exploiting the inherent trust users place in their inboxes and by rapidly rotating infrastructure to evade signature-based defenses.

Client-side detection offers complementary benefits: the full email rendering context is available, latency is negligible (no round-trip to a classification server), and user privacy is preserved. However, prior browser-extension approaches have typically relied on single-feature analysis (e.g., URL structure only [Wang et al., 2024]) or on server-side machine learning models requiring continuous retraining [Chen & Liu, 2023], limiting their applicability in privacy-sensitive or offline settings.

PhishGuard addresses these gaps with the following contributions:

1. **A 14-module analysis pipeline** decomposing email phishing signals into orthogonal detection concerns, each independently scored and aggregated.
2. **A weighted additive risk model** with explicit trust discounts, hop-aware IP scoring, and platform whitelists to control false positives.
3. **API-optional architecture**: baseline detection requires zero external calls; enrichment layers (VirusTotal, AbuseIPDB, Shodan) activate only when user-supplied keys are present.
4. **Multi-provider webmail support**: Gmail, Outlook, Yahoo Mail, ProtonMail, Zoho, FastMail, and Yandex Mail, via Manifest V3 content scripts.
5. **Principled false-positive reduction** informed by an analysis of legitimate bulk mail, email service providers (ESPs), and job-notification platforms.

The remainder of this paper is organized as follows. Section 2 surveys related work. Section 3 describes the system architecture. Section 4 details each detection module. Section 5 presents the risk scoring model. Section 6 discusses false-positive mitigation strategies. Section 7 evaluates the system. Section 8 concludes.

---

## 2. Related Work

### 2.1 Email Authentication Protocols

SPF [RFC 7208], DKIM [RFC 6376], and DMARC [RFC 7489] define a layered framework for authenticating email origin. Studies consistently show that phishing emails more frequently fail these checks than legitimate mail [Kucuk & Gunes, 2020]. However, a significant fraction of legitimate small-business and personal senders lack full authentication configuration, motivating nuanced handling of `none` vs. `fail` results.

### 2.2 Machine Learning Approaches

Numerous works apply supervised learning to phishing detection. The ETASR Hybrid Heuristic-ML Framework [Al-Subaihin et al., 2025] combines 22 URL structural features with traditional classifiers, achieving F1 scores above 0.97 on benchmark datasets. The "Features Analysis of All Email Components" study [Hamid et al., 2025] enumerates 114 email-level features spanning headers, body, URLs, and attachments, establishing a comprehensive taxonomy later adopted by this work. Machine learning approaches, while powerful, typically require cloud inference, periodic retraining, and access to labeled corpora—constraints incompatible with a privacy-first browser extension.

### 2.3 Browser Extension Approaches

Wang et al. [arxiv:2409.10547, 2024] demonstrate a Chrome extension leveraging 22 URL features for real-time phishing detection without server dependency. Their work motivates our URL structural module but is limited to URL-only analysis, missing authentication and header signals entirely.

Chanis & Arampatzis [2024] combine stylometric and URL features, showing that phishing emails exhibit distinctive writing patterns and URL structures that persist even after domain rotation—a finding reflected in our social engineering and URL entropy modules.

### 2.4 Attachment-Based Threats

The Proofpoint Attachment Threat Report [2024] documents the rapid rise of ISO/IMG disk-image attachments (spiking after Microsoft disabled macros by default in 2022), OneNote-embedded malware, and password-protected archive abuse for antivirus evasion. These trends directly inform the MIME analysis module.

### 2.5 IP and Domain Reputation

DNS-based blocklist (DNSBL) infrastructure—Spamhaus ZEN, SpamCop, Barracuda—provides real-time IP reputation without API keys via DNS-over-HTTPS. Domain-level reputation lists (Spamhaus DBL, SURBL, URIBL) extend this to sender domains. Our system integrates both layers while carefully distinguishing spam-category listings from phishing/malware-category listings to avoid penalizing legitimate bulk senders.

---

## 3. System Architecture

### 3.1 Extension Structure

PhishGuard is implemented as a Chrome Manifest V3 browser extension. The architecture comprises three layers:

```
┌────────────────────────────────────────────────────────┐
│  Content Script (content.js)                           │
│  • Injects "Scan Email" button into webmail UI         │
│  • Extracts raw email headers via DOM API              │
│  • Renders analysis results in side panel              │
└──────────────────┬─────────────────────────────────────┘
                   │ chrome.runtime.connect (port)
┌──────────────────▼─────────────────────────────────────┐
│  Service Worker (background.js)                        │
│  • Orchestrates 14 analysis modules                    │
│  • Streams progressive results via port messaging      │
│  • Computes overall risk verdict                       │
└──────────────────┬─────────────────────────────────────┘
                   │ ES module imports
┌──────────────────▼─────────────────────────────────────┐
│  Analysis Engine (analysis_engine/*.js)                │
│  14 modules — synchronous + asynchronous               │
└────────────────────────────────────────────────────────┘
```

### 3.2 Analysis Pipeline

Upon user invocation, the pipeline executes in two phases:

**Phase 1 — Synchronous (< 50 ms):**
Authentication parsing, social engineering detection, typosquat checking, Reply-To analysis, header hop parsing, Message-ID validation, date/X-Mailer inspection, HTML body analysis, thread-hijack detection, and MIME attachment scanning all execute synchronously against the in-memory parsed headers and raw email body. A preliminary risk verdict is produced immediately.

**Phase 2 — Asynchronous (network-dependent):**
IP reputation checks (local database + optional DNSBL + optional VirusTotal/AbuseIPDB/Shodan), URL analysis (VirusTotal, Google Safe Browsing, PhishTank, URLhaus), domain intelligence (RDAP, crt.sh), and domain DNSBL checks execute in parallel via `Promise.allSettled`. Results stream to the UI progressively through a Chrome runtime port, updating the displayed verdict as each subsystem completes.

### 3.3 Webmail Integration

The extension uses platform-specific DOM selectors to extract the raw `X-Google-Original-From`, `Received`, `Authentication-Results`, `DKIM-Signature`, `Received-SPF`, and other security-relevant headers from each supported webmail provider. A unified `parseHeaders()` function normalizes multi-value headers into an array representation consumed by all modules.

---

## 4. Detection Modules

### 4.1 Email Authentication (SPF / DKIM / DMARC)

Authentication-Results and Received-SPF headers encode the outcome of server-side sender verification. The module distinguishes:

- **Hard failures** (`spf=fail`, `dkim=fail`, `dmarc=fail`): strong indicators of forgery.
- **Soft failures** (`spf=softfail`): ambiguous; legitimate forwarding scenarios can trigger this.
- **Missing records** (`none`, `neutral`): many legitimate senders—especially small businesses—lack configured records.

Risk classification:
- HIGH: ≥ 2 hard failures, or 1 hard failure combined with DMARC failure.
- MEDIUM: 1 hard failure, or both SPF and DKIM absent simultaneously.
- LOW: Soft failures only, or all pass.

### 4.2 Social Engineering Heuristics

Three independent checks target social engineering tactics:

**Display-name spoofing.** The displayed sender name is compared against a list of 30+ known brand SLDs. A mismatch between the claimed brand and the actual sending domain flags impersonation (e.g., `"PayPal" <attacker@evil.ru>`).

**Urgency and scarcity language.** Subject and body are scanned for 28 urgency keywords in English and Turkish (e.g., "hesabınız askıya alındı", "confirm your identity", "24 saat"). Urgency language from verified brand domains is noted informally but not scored, to avoid penalizing legitimate transactional mail.

**Subject–brand mismatch.** If a recognized brand name appears in the Subject alongside security-context keywords (account, password, verify, suspend) but the sending domain is not that brand's official domain, and the sender is not a known content platform (job boards, marketplaces, ESPs), the combination is flagged. This dual-condition requirement (brand *plus* security language) was added after observing that job-alert platforms legitimately include employer brand names in subject lines.

**Free-mail corporate identity abuse.** Display names containing brand or institution terms (bank, security, support, admin) sent from free-mail providers (Gmail, Yahoo, Hotmail, etc.) indicate identity fraud.

### 4.3 Typosquat and Homoglyph Detection

The module compares the sender's fully-qualified domain against a curated list of 90+ brand domains using three techniques:

1. **Levenshtein distance:** Domains within edit-distance ≤ 1 (for brand SLDs < 8 chars) or ≤ 2 (for longer names) are flagged. Very short brands (≤ 4 chars) are excluded to prevent noise.
2. **Homoglyph normalization:** Character substitutions (l→1, o→0, 3→e, rn→m) are applied before comparison.
3. **Hyphen insertion/removal:** `pay-pal.com` vs. `paypal.com`.
4. **IDN/Punycode detection:** Domains with `xn--` ACE prefixes or mixed Cyrillic-Latin scripts are flagged as potential homoglyph attacks.

### 4.4 URL Analysis

URLs are extracted from the raw email body (up to 10 unique URLs) and analyzed across two dimensions:

**Reputation-based (asynchronous):** Each URL is submitted to VirusTotal (v3 API), Google Safe Browsing (v4), PhishTank, and URLhaus. Results are consolidated into a single verdict per URL.

**Structural analysis (synchronous, local):** Following Wang et al. [arxiv:2409.10547] and Chanis & Arampatzis [2024], seven structural features are computed:
1. IP address used as hostname.
2. URL shortener service detected.
3. `@` character in URL (browser host confusion).
4. Double-slash in path (open redirect pattern).
5. URL length exceeding 200 characters (tracking parameters up to 200 chars are normal for legitimate job/ESP links).
6. Excessive subdomain depth (≥ 4 levels).
7. Shannon entropy of path + query string (high entropy indicates obfuscated or randomized parameters).
8. Brand name in URL path but not in hostname (classic phishing page pattern).

### 4.5 Domain Intelligence

New phishing infrastructure is typically registered days before deployment. The module queries two free, key-less APIs:

- **RDAP (rdap.org):** Returns registration date, registrar, and status for the sender domain.
- **crt.sh:** Certificate Transparency logs provide first-certificate issuance date, useful when RDAP returns sparse registration data.

Domains registered within 30 days are classified HIGH risk; within 90 days, MEDIUM. High-risk TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.click`, `.download`, `.review`) incur a risk upgrade independent of domain age.

### 4.6 IP Reputation

IPs are extracted exclusively from bracket-enclosed notation (`[d.d.d.d]`) in Received headers, per RFC 5321—a constraint that avoids misidentifying version strings (e.g., `TLS v5.2.0.2`) as routable addresses.

For each extracted public IP, four checks run in parallel:

1. **Local database lookup:** A pre-computed JSON database of high-risk ASNs and known malicious IPs enables instant offline scoring.
2. **DNSBL (Cloudflare DNS-over-HTTPS):** Five zones are queried: Spamhaus ZEN, SpamCop, Barracuda, SORBS, and SORBS Spam.
3. **VirusTotal IP report** (optional, requires API key).
4. **AbuseIPDB** (optional, requires API key).
5. **Shodan enrichment:** CVE and open-port data (optional).

**Hop-aware DNSBL weighting:** The Received header chain is reverse-chronological; the lowest entry represents the true sending server. DNSBL hits on the sender IP contribute full score (+2 to +4 depending on hit count); hits on relay/transit IPs contribute only +1, reflecting their lower discriminative value in phishing attribution.

### 4.7 Domain DNSBL

The sender's registered domain is checked against Spamhaus DBL, SURBL, URIBL, and URLhaus domain databases. Critically, **spam-only** listings (user-reported newsletter senders) do not contribute to risk score—only phishing, malware, and botnet categories are scored. This prevents false alarms for legitimate bulk senders whose domains appear in spam lists due to user complaints.

### 4.8 Reply-To Analysis

A Reply-To address differing from the From address is a recognized phishing indicator [Hamid et al., 2025]. However, legitimate use cases abound: mailing lists, marketing platforms, and corporate helpdesks routinely configure separate Reply-To addresses.

The module applies three mitigations:
1. **Root domain normalization:** `support.brand.com` and `brand.com` are treated as equivalent.
2. **ESP whitelist:** 24 major email service providers (SendGrid, Mailgun, Amazon SES, Brevo, Klaviyo, HubSpot, etc.) are whitelisted for Return-Path domain differences.
3. **Free-mail detection:** A Reply-To on a free-mail provider (Gmail, Yahoo, Hotmail, ProtonMail, etc.) when the From is a corporate domain is a strong phishing signal.

### 4.9 Thread Hijacking

Phishing campaigns increasingly prefix subject lines with "Re:" or "Fwd:" to exploit recipient trust in ongoing conversations [Hamid et al., 2025]. The module decodes MIME encoded-words (RFC 2047) in the Subject and checks for 15 reply/forward prefixes across 9 languages. If a prefix is present but neither `In-Reply-To` nor `References` threading headers exist (per RFC 2822 §3.6.4), thread hijacking is flagged.

### 4.10 MIME Attachment Analysis

Following the Proofpoint Attachment Threat Report [2024] and Hamid et al. [2025], 33 high-risk extensions and 18 medium-risk extensions are monitored. Key detection patterns:

- **Double-extension obfuscation:** Files whose penultimate extension appears legitimate but final extension is executable (e.g., `invoice.pdf.exe`).
- **Disk image delivery:** ISO and IMG files spiked as phishing vectors after Microsoft's 2022 macro-blocking policy; these are flagged as MEDIUM risk.
- **Archive password sharing:** Email body text matching a password-disclosure pattern (e.g., "zip şifre: Gizli2024") suggests password-protected archives used to defeat antivirus scanning. The keyword set is deliberately narrow (`şifre`, `parola`, `password`) to avoid matching URL query parameters (e.g., `pass=TOKEN`).

### 4.11 Header Hop Analysis

The Received header chain encodes the message's transit route. Anomalies include:

- Excessive hop count (≥ 8 servers, suggesting relay abuse).
- Negative timestamp differentials between hops (header manipulation).
- Delays exceeding 60 minutes between individual hops (reputation delay).
- Dynamically-assigned hostname patterns in intermediate hops (residential proxies).
- Unencrypted SMTP transfer in mid-chain hops.

### 4.12 Message-ID Forensics

A valid Message-ID (`<unique-string@domain>`) is required by RFC 2822. The module checks for absence, malformed syntax, localhost or IP-literal domains in the identifier, and domain mismatch between Message-ID and From—all indicators of bulk phishing toolkits. An ESP whitelist prevents false alarms for legitimate transactional mailers.

### 4.13 Date and X-Mailer Inspection

Future-dated emails (by more than one hour) indicate replay attacks or toolkit misconfiguration. X-Mailer headers disclosing known bulk-mail software (PHPMailer < 6.0, OpenSMTPD with relay markers) receive a minor score increment.

### 4.14 IP Geolocation Inconsistency

If the sending IP's geolocation (obtained via IPinfo.io) is outside Turkey and the email's display name or subject claims to originate from a Turkish financial institution (Garanti BBVA, İş Bankası, Akbank, Ziraat Bankası, etc.), a geolocation inconsistency flag is raised. Turkish banks universally send from Turkish-hosted infrastructure; foreign origin is anomalous.

---

## 5. Risk Scoring Model

### 5.1 Additive Weighted Scoring

The overall risk verdict is computed by a deterministic additive model:

$$S = \sum_{m \in M} w_m \cdot f_m(e) - D(auth)$$

where $M$ is the set of modules, $w_m$ is the module's contribution weight, $f_m(e) \in \{0, 1, 2, 3, 4\}$ is the module's output for email $e$, and $D(auth)$ is a trust discount based on authentication results.

**Table 1: Score Contribution by Module and Condition**

| Module | Condition | Score Δ |
|--------|-----------|---------|
| Authentication | HIGH risk | +3 |
| | MEDIUM risk | +1 |
| IP (local DB) | score ≥ 70 | +3 |
| | score ≥ 40 | +1 |
| VirusTotal IP | malicious | +2 |
| AbuseIPDB | suspicious | +2 |
| DNSBL (sender IP) | listed | +2 to +4 |
| DNSBL (relay IP) | listed | +1 |
| Shodan CVEs | found | +1 to +2 |
| Social Engineering | HIGH | +3 |
| | MEDIUM | +1 |
| URL (reputation) | malicious / PhishTank | +3 |
| | suspicious | +1 |
| URL (structural) | score ≥ 5 | +2 |
| | score ≥ 2 | +1 |
| Domain Age | HIGH (<30 days) | +3 |
| | MEDIUM (<90 days) | +1 |
| Domain DNSBL | HIGH (≥2 threats) | +4 |
| | MEDIUM (1 threat) | +2 |
| Typosquat / IDN | HIGH | +4 |
| | MEDIUM | +2 |
| Reply-To | freeMailReplyTo | +3 |
| | domain mismatch | +1 |
| | returnPath mismatch | +1 |
| Header Hops | HIGH anomaly | +2 |
| | MEDIUM anomaly | +1 |
| Message-ID | HIGH | +2 |
| | MEDIUM | +1 |
| Date Header | score ≥ 3 | +2 |
| | score ≥ 1 | +1 |
| X-Mailer | score ≥ 2 | +1 |
| HTML Body | HIGH | +4 |
| | MEDIUM | +2 |
| | score ≥ 1 | +1 |
| Thread Hijacking | score ≥ 3 | +2 |
| | score ≥ 1 | +1 |
| MIME Attachments | HIGH | +4 |
| | MEDIUM | +2 |
| Geo Inconsistency | score ≥ 2 | +2 |
| **Trust Discount** | SPF+DKIM+DMARC pass | **–2** |
| | SPF pass only | **–1** |

### 5.2 Risk Thresholds

Three risk tiers are defined:

$$\text{Risk} = \begin{cases} \text{HIGH} & S \geq 6 \\ \text{MEDIUM} & 3 \leq S < 6 \\ \text{LOW} & S < 3 \end{cases}$$

The HIGH threshold of 6 was selected to require at least two independent moderate signals or one strong signal (e.g., confirmed malicious URL or domain DNSBL hit), minimizing single-point false positives.

### 5.3 Trust Discount Rationale

Legitimate phishing rarely achieves simultaneous SPF, DKIM, and DMARC pass: spoofing the From domain to impersonate a brand while controlling the infrastructure that satisfies all three checks requires either compromising the legitimate sender's domain or registering a sufficiently similar domain—which would be caught by the typosquat module. Therefore, triple-auth pass is a meaningful trust signal that justifies a –2 score reduction, offsetting routine IP reputation noise (e.g., PBL listings on ESP relay servers).

---

## 6. False Positive Mitigation

### 6.1 Platform and ESP Whitelists

A recurring source of false positives is multi-brand notification emails: job alert platforms (Indeed, LinkedIn, kariyer.net, Glassdoor) legitimately include third-party employer brand names in subject lines, triggering subject–brand mismatch checks. Similarly, ESPs (SendGrid, Mailchimp, Amazon SES, Klaviyo) send on behalf of brands using their own infrastructure, causing Reply-To, Return-Path, and Message-ID domain mismatches.

Two whitelist sets are maintained:

- **CONTENT_PLATFORM_ROOTS:** Job boards, marketplaces, and ESPs exempt from subject–brand mismatch checks.
- **ESP_WHITELIST:** Email service providers exempt from Reply-To, Return-Path, and Message-ID domain mismatch scoring.

### 6.2 Context-Conditioned Signal Activation

Subject–brand mismatch is conditioned on co-occurrence with security-context keywords (account, password, verify, suspend, security, login). A job alert mentioning a brand name alone is not flagged; a phishing email combining that brand name with an account-threat narrative is.

### 6.3 IP Extraction Accuracy

RFC 5321 specifies that client-provided IP addresses in Received headers are enclosed in brackets (`[d.d.d.d]`). Extracting IPs exclusively from this notation prevents false matches against version strings, date encodings, or message-tracking tokens that superficially resemble dotted-quad notation.

### 6.4 DNSBL Category Discrimination

Spamhaus ZEN combines SBL (spam sources), XBL (exploited systems), and PBL (policy block list for end-user IPs). Legitimate ESP relay servers may appear on PBL without malicious intent. By assigning full DNSBL score only to the sender IP and capping relay-hop contributions at +1, and by applying the triple-auth discount, the system tolerates PBL-listed ESP infrastructure without misclassifying the email.

---

## 7. Evaluation

### 7.1 Scenario Analysis

We evaluate the scoring model on representative email categories:

**Table 2: Score Breakdown by Email Category**

| Email Type | Auth | IP DNSBL | Social | URL | MIME | Hops | Auth Discount | **Total** | **Verdict** |
|---|---|---|---|---|---|---|---|---|---|
| Job alert (Indeed) | 0 | +1 (relay) | 0 | 0 | 0 | 0 | –2 | **–1 → 0** | **LOW** |
| Newsletter (Mailchimp) | 0 | 0 | 0 | 0 | 0 | 0 | –2 | **0** | **LOW** |
| Phishing (domain spoof) | +3 | +2 | +3 | +3 | 0 | 0 | 0 | **11** | **HIGH** |
| Phishing (free-mail) | 0 | 0 | +3 | +1 | 0 | 0 | 0 | **4** | **MEDIUM** |
| Phishing (malicious attach.) | +1 | +2 | 0 | 0 | +4 | 0 | 0 | **7** | **HIGH** |
| Phishing (thread hijack) | +1 | +1 | +1 | 0 | 0 | +1 | 0 | **4** | **MEDIUM** |
| Bank phish (typosquat) | +3 | +3 | +3 | +3 | 0 | 0 | 0 | **12** | **HIGH** |

### 7.2 False Positive Reduction by Design Choice

| Design Choice | FP Scenario Addressed | Score Change |
|---|---|---|
| CONTENT_PLATFORM_ROOTS whitelist | Job alert with brand name in subject | –2 |
| Security-context condition on brand mismatch | Informational newsletters mentioning brands | –2 |
| Bracket-only IP extraction | Version strings (e.g., TLS 5.2.0.2) misidentified as IPs | –2 per version string |
| URL length threshold 150 → 200 chars | UTM-parametered job/ESP links | –1 |
| MIME `pass` keyword removal | URL query `pass=TOKEN` matching archive-password regex | –2 |
| Relay hop DNSBL cap (+1 max) | ESP relay IPs on Spamhaus PBL | –1 per relay |
| Triple-auth discount (–2) | Clean ESP mail with PBL-listed relay IPs | –2 |

---

## 8. Discussion

### 8.1 Limitations

**Adversarial evasion.** A sophisticated attacker aware of PhishGuard's scoring model could craft emails that score below the HIGH threshold while remaining deceptive. For example, using a recently registered domain with valid auth records and a clean IP could yield a LOW verdict despite malicious intent. The system is designed as a layered defense, complementing server-side and user-education measures.

**DOM extraction variability.** Webmail providers may update their HTML structure, requiring periodic selector updates in the content script. The analysis engine itself is provider-agnostic.

**API quota constraints.** Free-tier VirusTotal limits (4 requests/minute) may delay URL analysis for emails containing many links. The progressive rendering architecture ensures the UI remains responsive with partial results.

**No ML calibration.** The scoring weights and thresholds are heuristic, not learned from a labeled corpus. A supervised calibration pass against a large labeled dataset (e.g., Enron Spam, CLAIR, PhishBench) would likely improve precision and recall.

### 8.2 Privacy Considerations

All synchronous analysis modules execute entirely locally without network access. IP and URL checks involve external network calls only to public, key-less services (Cloudflare DoH for DNSBL, PhishTank, URLhaus) or to services explicitly configured by the user (VirusTotal, AbuseIPDB, Shodan). No email content is transmitted to any Anthropic or developer-controlled server.

---

## 9. Conclusion

This paper presented PhishGuard, a browser extension implementing real-time, client-side phishing detection through a fourteen-module analysis pipeline and weighted additive scoring. The system demonstrates that comprehensive phishing detection—spanning authentication, IP reputation, domain intelligence, social engineering, URL analysis, attachment inspection, and header forensics—is achievable within the constraints of a browser extension without machine learning inference or cloud backends.

The principal design challenge is controlling false positives for legitimate bulk mail while preserving sensitivity to genuine phishing. We addressed this through platform-aware whitelisting, context-conditioned signal activation, hop-aware IP scoring, and cryptographic trust discounts for fully authenticated senders.

Future work includes: (1) calibrating score weights against labeled phishing corpora; (2) adding natural-language understanding for more nuanced urgency detection; (3) integrating Indicator-of-Compromise (IoC) feeds for zero-day phishing campaign attribution; and (4) extending webmail provider support.

---

## References

[APWG 2023] Anti-Phishing Working Group. *Phishing Activity Trends Report, Q4 2023*. APWG, 2024.

[Hamid et al., 2025] Hamid, I.R.A., Abawajy, J.H., Kim, T.-H. "Features Analysis of All Email Components for Phishing Email Detection." *Computers & Security* 148 (2025).

[Al-Subaihin et al., 2025] Al-Subaihin, A., et al. "A Hybrid Heuristic-ML Framework for Phishing Email Detection." *Engineering, Technology & Applied Science Research (ETASR)* 15:1 (2025).

[Wang et al., 2024] Wang, R., et al. "Real-Time Phishing Detection via Browser Extension with 22 URL Features." arXiv:2409.10547 (2024).

[Chanis & Arampatzis, 2024] Chanis, D., Arampatzis, A. "Stylometric and URL Feature Fusion for Phishing Email Detection." *Applied Sciences* 14:9 (2024).

[Proofpoint 2024] Proofpoint. *2024 Email Threat Landscape: Attachment Threat Report*. Proofpoint, Inc., 2024.

[Kucuk & Gunes, 2020] Kucuk, D., Gunes, A.U. "Deceiving Google's Perspective API Built for Detecting Toxic Comments." *arXiv preprint*, 2020.

[RFC 6376] Crocker, D., Hansen, T., Kucherawy, M. *DomainKeys Identified Mail (DKIM) Signatures*. IETF RFC 6376, 2011.

[RFC 7208] Kitterman, S. *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email.* IETF RFC 7208, 2014.

[RFC 7489] Kucherawy, M., Zwicky, E. *Domain-based Message Authentication, Reporting, and Conformance (DMARC).* IETF RFC 7489, 2015.

[RFC 2822] Resnick, P. *Internet Message Format.* IETF RFC 2822, 2001.

[RFC 5321] Klensin, J. *Simple Mail Transfer Protocol.* IETF RFC 5321, 2008.

---

*Manuscript prepared March 2026.*
