# Benign-URL Dataset Review (Option C)

Investigation only. Nothing was downloaded beyond web pages, and no model, dataset, extractor, API or extension file was changed.

Every statement below comes from the dataset's own card or paper, or is marked as not stated. Nothing here comes from opening the data itself.

## 1. Best candidate: PhreshPhish

| Item | Finding | Source |
| :--- | :--- | :--- |
| Name | PhreshPhish, official repository `phreshphish/phreshphish` on Hugging Face | Dataset card |
| Paper | Dalton et al., 2025, "PhreshPhish: A Real-World, High-Quality, Large-Scale Phishing Website Dataset and Benchmark", arXiv 2507.10854 | Card, paper |
| Licence | **CC BY 4.0**. The card adds that it "should only be used for anti-phishing research" | Dataset card |
| Version and date | v1.0.1, 2026-02-07. Collected July 2024 to December 2025 | Card, paper |
| Size | Train 498,255 (276,729 benign, 221,526 phishing). Test 168,060 (91,260 benign, 76,876 phishing) | Card |
| Fields | `url`, `label`, `target`, `date`, `sha256`, `lang`, `lang_score`, `html` | Dataset viewer |
| Format | Parquet in 50 train files and test files, 36.6 GB in total because HTML is included | Repository listing |
| Access | No gating or access request is mentioned | Card |

### 1.1 Where the benign URLs come from

| Question | Answer |
| :--- | :--- |
| Source | "Anonymized browsing telemetry from over six million global Webroot users and Google search results for heavily targeted brands" |
| Realistic paths | Yes. Real browsed pages. The paper reports benign path lengths with a median of 29 characters |
| Query strings | **Removed.** The paper says query parameters are stripped from the URL |
| Label method for benign | Not described as a separate verification. Benign means "was browsed" or "came from a brand search", filtered for missing HTML, bad titles and person names |
| Label method for phishing | PhishTank, APWG eCrime eXchange and Netcraft |
| Error rate | The authors state they "do not claim that our dataset is free of all errors". Manual review removed under 1% of phishing and "a negligible number" of benign samples |
| Deduplication | URLs canonicalised and deduplicated. Near-duplicates are filtered between train and test using TF-IDF similarity |
| Split | **Temporal.** Test is strictly later than train. Separation by domain is not stated |

### 1.2 Limitations to respect

| Limitation | Why it matters here |
| :--- | :--- |
| Benign means "browsed", not "proven safe" | A small number of malicious URLs can sit in the benign class. This cannot be audited from the card |
| Query strings removed | Our `query_parameter_count` feature will not learn from this data. Real URLs at prediction time do have queries |
| Telemetry from one vendor's users | Skewed by that user base, geography and software |
| Phishing from PhishTank | Overlaps with our current phishing data, so it is not independent for that class |
| Domain split not stated | We must create our own domain split, as planned |
| Phishing pages "systemically easier to scrape" | Possible over-representation of some kinds of phishing |
| Privacy | Paths came from real browsing. Authors removed person names but state that email addresses and phone numbers were not removed from benign page HTML |
| Dual use | The authors acknowledge it |
| Card inconsistency | The card's test counts add up to 168,136, not 168,060. Minor, but the numbers need checking when opened |

### 1.3 What I have not verified

- The actual `url` values, so the real fraction of benign rows with a path and the share of `?` in each class are unknown.
- Whether query stripping was applied to **both** classes. The paper text I read was ambiguous. If only benign was stripped it would create a new shortcut.
- The last 12,878 characters of the paper, which may hold more limitations.
- The full file list. The folder page showed 50 of the files.

## 2. Other candidates

| Dataset | Licence | Benign source and method | Paths | Age | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PhiUSIIL** (UCI 967) | CC BY 4.0 | Source of legitimate URLs **not stated** on the UCI page. 134,850 legitimate, 100,945 phishing | Not stated | Mostly 2023 | Cannot justify labels without reading the paper. Second choice |
| **ISCX-URL2016** (UNB CIC) | **Not stated** | Alexa top sites crawled with Heritrix, then filtered through VirusTotal. About 35,300 benign | Yes, crawled | 2016 | Provenance is clear, but the licence is unstated and the data is ten years old |
| Common Crawl-based Mendeley sets | Not checked | Common Crawl, sometimes mixed with ranking lists | Unclear | 2024 to 2026 | Not verified. Benign sides are mostly domain-level |
| URL-Phish (Mendeley) | Not checked | `.edu`, `.gov` and top-ranked domains | No, features only | 2025 | Unsuitable. Raw URLs not provided |
| StealthPhisher2025 (already audited) | Unknown | Unknown | **No** | Unknown | Rejected in Phase 2 |

I did not use ranking membership or popularity as evidence of legitimacy for any candidate.

## 3. How PhreshPhish could be combined with our data

Not started. This is the proposal for your review.

### 3.1 Getting only what we need

- The files are Parquet, a column-based format. We need only `url`, `label` and `date`.
- That can be read **without downloading 36.6 GB**, by reading just those columns from each file.
- **Pilot first:** read `url`, `label`, `date` from the smallest file (`train-000.parquet`, about 50 MB) and inspect it. Expected time is under a few minutes and the transfer is a small fraction of the file. No training.

### 3.2 Steps after the pilot, each needing your approval

| Step | Action |
| :--- | :--- |
| 1 | Verify the pilot: share of benign rows with paths, `?` share per class, URL shapes, duplicates inside the file |
| 2 | Normalise URLs (lowercase host, trailing slash) and remove exact and near duplicates within PhreshPhish |
| 3 | Remove rows that overlap our current dataset by exact URL or by domain, and record the counts |
| 4 | Assign every **domain** to either training or evaluation, never both. Keep a second, time-based holdout using the `date` field |
| 5 | Cap rows per domain so a few sites cannot dominate |
| 6 | Run the existing 32-feature extractor unchanged and keep the feature order |
| 7 | Record rows accepted, rejected and deduplicated, with reasons, in a data report |
| 8 | Only then train a separate candidate model under a new filename, leaving v3 active |

### 3.3 Handling the query-string gap

- Phishing URLs in the same dataset may or may not have queries removed. This must be checked in the pilot.
- If both classes are stripped, training on them is consistent, and the `query_parameter_count` feature simply carries no signal from this data.
- If only benign is stripped, the pilot result decides whether to strip queries from every training URL for consistency, or to drop PhreshPhish.

### 3.4 Handling the label risk

- Benign labels are accepted from the dataset's stated method, and the report will say so plainly.
- A benign row will not be treated as safe because of its hostname, and no row will be relabelled by hostname.
- Rows that appear in both classes after normalisation are removed, not resolved.

## 4. Licence and privacy conditions

| Condition | What we do |
| :--- | :--- |
| Attribution (CC BY 4.0) | Cite the paper in the README and the data report |
| Anti-phishing research only | The project's purpose fits. Do not reuse the data for other purposes |
| Privacy | Keep the extracted URLs on this machine only. Do not commit them. Add them to `.gitignore` as for the other training data |
| Redistribution | Do not republish the extracted CSV |

## 5. Verdict

PhreshPhish is the only candidate with a clear source, a clear licence, a recent collection date and **real benign URLs with realistic paths**. It is not perfect. Benign labels rest on browsing telemetry, query strings are removed, and the split is temporal not by domain.

It is suitable as the next step **if the pilot confirms** the URL shapes and the query-string question. If it does not, the remaining options are:

1. Collect owner-published sitemaps from reputable sites (the earlier option A).
2. Use ISCX-URL2016 for its crawled paths, accepting its age and unstated licence.
3. Keep v3 and only add capped phishing rows.

## 6. Decision needed

Approve one of:

- **Pilot:** read `url`, `label` and `date` from `train-000.parquet` only, inspect it, and report. No training and no change to existing files.
- **Different source:** pick another option from section 5.
- **Stop:** keep v3 as it is.
