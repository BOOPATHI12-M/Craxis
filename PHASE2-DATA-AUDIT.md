# Phase 2: Dataset Audit

Read-only investigation. No model, dataset, extractor or extension file was changed. The only addition is this report.

## 1. Result in one paragraph

The current model's schema is clean and every StealthPhisher URL can be run through the existing feature extractor. But the file **has no legitimate URLs with paths**, which was the main thing we wanted from it. Its phishing side is large but heavily concentrated, and its labels have no recorded source. So Phase 3 cannot start as planned. A source of legitimate URLs with real paths is the missing piece.

## 2. The current model's exact schema

| Item | Value |
| :--- | :--- |
| Algorithm and version | Random Forest, 3.0 |
| Input count | 32, equal to the model's `n_features_in_` |
| Feature names stored in the model | Identical to `FEATURE_NAMES` in `feature_extractor.py` |
| Input source | The URL string only, nothing else |
| Preprocessing | None. Raw numbers go straight into the forest |

The 32 features, in order:

`url_length`, `hostname_length`, `path_length`, `dot_count`, `hyphen_count`, `subdomain_count`, `digit_count`, `special_character_count`, `query_parameter_count`, `fragment_count`, `https`, `has_ip`, `has_at_symbol`, `suspicious_encoding_count`, `suspicious_keyword_count`, `hostname_entropy`, `excessive_subdomain_depth`, `unusual_port`, `is_shortened_url`, `is_punycode`, `hostname_hyphen_count`, `hostname_digit_ratio`, `path_depth`, `suspicious_tld`, `brand_in_domain`, `brand_lookalike`, `on_shared_hosting`, `site_label_length`, `site_label_digit_ratio`, `site_label_consonant_run`, `site_label_vowel_ratio`, `tld_length`

Keyword, brand, TLD and shared-hosting lists come from `shared/config.json`, so they are fixed and shared with the extension.

## 3. How StealthPhisher records map to this schema

| Question | Answer |
| :--- | :--- |
| Can its records be used with our schema? | **Yes, by URL.** The 62 StealthPhisher columns are not needed |
| Does the extractor run on them? | Yes. 5,000 random URLs, 0 exceptions, 0 wrong-length or NaN vectors |
| Is the label mapping simple? | Yes. `Phishing` becomes 1 and `Legitimate` becomes 0. Every row has one of the two |
| Can the labels be justified? | **Not from the files.** No source, date or verification method is recorded |

## 4. The legitimate side

This is the important finding. The URL strings were parsed, not the CSV column `HavingPath`.

| Property of the 160,943 legitimate rows | Value |
| :--- | ---: |
| URLs with a path | **2** (`https://www.iliad.it/account/ricarica`, `https://www.lapostegroupe.com/fr`) |
| URLs with a query | 0 |
| HTTPS | 100% |
| Distinct registrable domains | 153,681 |
| Share held by the top 10 domains | 1.0% |
| Domains in the Tranco top 1M | 16.7% |
| Domains outside the Tranco top 1M | 83.3% (134,109 rows) |

So the legitimate class is almost entirely `https://<domain>` home pages. It is diverse across domains, which is good, but it contains no examples of what a real legitimate page URL looks like.

**Consequence:** using these rows as legitimate training data would teach the model "no path means legitimate", which is the same shortcut that made the 62-feature model look excellent and fail elsewhere.

**Not done on purpose:** 83% of the legitimate domains are not in a popularity list. I did not assume they are legitimate because of their hostname. Their label comes only from the dataset and cannot be checked here.

## 5. The phishing side

| Property of the 175,806 phishing rows | Value |
| :--- | ---: |
| Distinct registrable domains | 40,884 |
| Share held by the top 10 domains | **37.5%** |
| On shared hosting platforms | 27.0% |
| With a path | 54.7% |
| HTTPS | 71.0% |
| Rows on domains in the Tranco top 10k | 70,308 (40.0%) |

Largest sources:

| Domain | Rows |
| :--- | ---: |
| `gitbook.io` | 11,876 |
| `87.120.115.240` (one IP address) | 10,458 |
| `google.com` | 9,927 |
| `weeblysite.com` | 6,525 |
| `r2.dev` | 5,677 |
| `web.app` | 4,815 |
| `firebaseapp.com` | 4,657 |
| `cf-ipfs.com` | 4,238 |

These are mostly abused hosting and form platforms. The phishing label is about the page, not the platform, so the rows can be valid. But one IP address supplies 6% of all phishing and a handful of platforms supply over a third, so a model trained on them without caps would mostly learn those few hosts.

## 6. Duplicates and label quality

| Check | Result |
| :--- | ---: |
| Exact duplicate URLs | 0 |
| Duplicate groups after normalising (case, `www`, trailing slash) | 6,124 groups, 12,488 rows |
| Normalised duplicates with conflicting labels | 25 groups |
| Hostnames labelled both phishing and legitimate | 35 hostnames, 93 rows |
| Registrable domains labelled both ways | 240 domains, 9,194 rows |
| URLs containing whitespace | 1,627 |

The 240 mixed domains are mostly hosting platforms and large sites with both a legitimate home page and abused pages. They cannot be resolved by looking at the hostname, so they need either a URL-level rule or exclusion.

## 7. Overlap with the current dataset

| Check | Result |
| :--- | ---: |
| Exact URLs present in both | 4,790 |
| Of those, label agreement | 4,789 agree (all phishing), 1 differs |
| Registrable domains present in both | 2,758 |
| Of those, domains where the labels differ by more than half | 102 |
| StealthPhisher rows whose domain is in the current dataset | 62,850 |

The one disagreement is `https://www.setupyouraccounts.com/`: labelled legitimate in StealthPhisher and phishing in PhishTank. It is a reminder that either source can be wrong.

The overlap means StealthPhisher is **not independent** of the current data. Any held-out evaluation must keep these domains on one side only.

## 8. Leakage and risk summary

| Risk | Finding |
| :--- | :--- |
| Class shortcut | Legitimate = home page and HTTPS only. Highest risk |
| Source concentration | A few platforms and one IP dominate phishing |
| Domain overlap with current data | 2,758 domains. Needs domain-grouped splitting |
| Label provenance | Unknown |
| Mixed-label domains | 240 domains, 9,194 rows |
| Crawl age | Unknown, so URLs may be offline or reused |

## 9. What is missing

A required input for Phase 3 is **legitimate URLs with realistic paths and a label that can be justified**. This file has none, and the existing dataset only has synthetic paths.

Options for obtaining it. I have not done any of them, and they need your decision.

| Option | What it means | Label justification | Cost and risk |
| :--- | :--- | :--- | :--- |
| A. Published sitemaps | Download `sitemap.xml` from well-known sites that publish one. The site owner lists these URLs itself | The owner published them. Excludes shared hosting and user-content domains | Needs network access and respect for `robots.txt`. A hacked site could still appear |
| B. Your own browsing history | Export URLs you actually visited | You visited them, which does not prove they are safe | Private data. Needs your consent. Labels unverified |
| C. A published benign-URL dataset | Another research dataset with real benign paths | Depends on that dataset's method | Licence and quality check needed |
| D. Use StealthPhisher for phishing only | Add capped, deduplicated phishing rows and keep the current synthetic legitimate class | Phishing labels still unverified | Does not fix the path bias |

**Recommendation:** option A for the legitimate class, combined with the phishing rows from StealthPhisher after capping each domain. Phase 3 would then record accepted, rejected and deduplicated counts as planned.

## 10. Stop point

Phase 3 should not start until a source of legitimate URLs with paths is chosen. Building a "better" dataset from this file alone would only add more home-page legitimate rows and make the shortcut worse.
