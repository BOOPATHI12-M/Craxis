# PhreshPhish Full Audit (URL, label, date only)

All 77 Parquet files were read with HTTP range requests, taking only the `url`, `label` and `date` columns. The HTML column was never transferred. No dataset was built, no model was trained and no project file was changed.

The extracted table is outside the project at `%TEMP%\phresh_full\phreshphish_urls.parquet`.

## 1. What was transferred

| Item | Value |
| :--- | ---: |
| Files read | 77 (56 train, 21 test) |
| Rows | 666,315 |
| Data transferred | 26.6 MB of 36.6 GB (0.07%) |
| Time | about 5 minutes |
| Benign / phishing | 367,989 / 298,326 |
| Train rows | 498,255 (276,729 benign, 221,526 phishing) |
| Test rows | 168,060 (91,260 benign, **76,800** phishing) |
| Dates | 2024-07-02 to 2025-12-16 |

The card says the test set has 76,876 phishing rows. The data has 76,800, so the card's figure is wrong by 76.

## 2. The full-set picture

| Property | Benign | Phishing |
| :--- | ---: | ---: |
| Rows | 367,989 | 298,326 |
| Distinct registrable domains | 119,847 | 63,641 |
| URLs with a path | **92.7%** | 49.2% |
| Deep path (2 or more segments) | **73.5%** | 20.7% |
| Median path length | **30** | 1 |
| URLs with a query | **0.0%** | 11.6% |
| URLs with a fragment | 0.0% | 0.5% |
| HTTPS | 97.8% | 86.2% |
| HTTP | 0.6% | 13.8% |
| No scheme at all | **1.56%** | 0.0% |
| Starts with `www.` | **57.2%** | 7.1% |
| On shared hosting | 0.2% | **31.5%** |
| IP-address host | 0.0% | 0.27% |
| HTML entities in the URL | 0.0% | 1.36% |
| Top 10 domains' share | 11.7% | **36.3%** |

The pilot's figures held up on the full set. The class differences are even larger for deep paths (73.5% against 20.7%) and `www.` (57% against 7%).

### 2.1 Concentration

| | Largest domains |
| :--- | :--- |
| Benign | `wikipedia.org` 15,184, `reddit.com` 4,026, `facebook.com` 3,827, `2mdn.net` 3,467, `amazon.com` 3,084 |
| Phishing | `gitbook.io` 19,872, `webflow.io` 19,689, `pages.dev` 15,475, `google.com` 12,372, `weeblysite.com` 8,509 |

## 3. Findings that matter

### 3.1 The class mix depends heavily on the collection month

| Month | Rows | Phishing share |
| :--- | ---: | ---: |
| 2024-07 | 53,556 | **99.7%** |
| 2024-08 | 99,991 | 15.3% |
| 2024-09 | 104,004 | 27.6% |
| 2024-10 | 39,086 | 61.9% |
| 2024-11 to 2025-04 | 40,255 | **100%** |
| 2025-06 | 11,485 | 41.1% |
| 2025-07 | 58,372 | 23.5% |
| 2025-08 | 55,348 | 25.2% |
| 2025-09 | 43,846 | 17.1% |
| 2025-10 | 114,043 | 46.8% |
| 2025-11 | 21,308 | 90.1% |
| 2025-12 | 1,017 | **0%** |

Some months are entirely phishing and one is entirely benign. A model can learn campaign-specific or period-specific URL patterns that say nothing about phishing in general. About 526,000 rows fall in months that contain both classes in reasonable proportion (10 to 90% phishing).

### 3.2 The dataset's own split is not separated by domain

| Check | Result |
| :--- | ---: |
| Domains present in both train and test | 17,109 |
| Rows on those domains | 404,351 of 666,315 (61%) |
| Normalised duplicate groups spanning train and test | 35 |

The authors' temporal split removes near-duplicates, but 61% of rows still share a domain across the split. Any evaluation must use our own domain-grouped split.

### 3.3 Shortcuts the data would teach

| Single feature | ROC-AUC alone | Direction |
| :--- | ---: | :--- |
| `path_length` | 0.802 | Longer path means benign |
| `path_depth` | 0.794 | Deeper path means benign |
| `hostname_entropy` | 0.734 | Higher means phishing |
| `hostname_length` | 0.725 | Longer means phishing |
| `url_length` | 0.699 (after stripping queries) | |
| `hostname_hyphen_count` | 0.665 | More hyphens means phishing |

Stripping queries and decoding entities does not remove the path shortcut. Query presence (0% against 11.6%) and `www.` (57% against 7%) are further shortcuts that cleaning alone does not address.

### 3.4 Label and quality issues

| Check | Result |
| :--- | ---: |
| Exact duplicate URLs | 0 |
| Normalised duplicate groups (scheme, `www`, slash, query, fragment ignored) | 15,115 groups, 20,220 removable rows |
| Normalised groups with conflicting labels | 6 groups, 27 rows |
| Registrable domains labelled both ways | **621 domains, 151,303 rows** |
| URLs that make `urlparse` raise an error | 1 (phishing) |
| URLs containing whitespace | 16 |
| Benign rows with no scheme | 5,742 |

The 621 mixed domains are mostly hosting and large multi-purpose sites. They cannot be resolved by hostname, so URL-level treatment is needed.

## 4. Cleaning accounting (counts only, nothing was written)

| Step | Rows rejected |
| :--- | ---: |
| Starting rows | 666,315 |
| No scheme | 5,742 |
| Scheme other than http or https | 0 |
| Unparseable URL | 0 after the scheme rule |
| Contains whitespace | 16 |
| Normalised duplicate (first kept) | 20,184 |
| Conflicting label on the same URL | 5 |
| **Rows remaining** | **640,368** (362,096 benign, 278,272 phishing) |

Effect of limiting how many rows one domain may contribute:

| Cap per domain | Rows | Benign | Phishing |
| ---: | ---: | ---: | ---: |
| 5 | 275,681 | 186,970 | 88,711 |
| 20 | 339,494 | 232,535 | 106,959 |
| 50 | 378,533 | 258,346 | 120,187 |

Domain capping removes most phishing rows, because that class is concentrated on few platforms.

## 5. Overlap with our other sources

| Check | Result |
| :--- | ---: |
| Exact URLs also in our current dataset | 2,508 |
| Label agreement on those | 2,476 phishing agree, 32 benign agree, **0 disagreements** |
| Domains also in our current dataset (kept rows) | 4,273 of 252,445, covering 103,972 rows |
| Exact URLs also in StealthPhisher | 46,508 |
| Label agreement on those | 46,498 phishing agree, 1 benign agrees, **9 disagreements** |
| Domains also in StealthPhisher (kept rows) | 24,992 covering 182,948 rows |

Most of PhreshPhish's phishing URLs also appear in StealthPhisher. They share an origin, so using both would count the same phishing pages twice.

Examples of disagreement with StealthPhisher (benign in one, phishing in the other): `https://www.iliad.it/account/ricarica`, `https://www.unesco.gov.ph`. These cannot be settled from the files.

## 6. Verdict

| Question | Answer |
| :--- | :--- |
| Does it supply realistic legitimate URLs with paths? | **Yes.** 73.5% of benign rows have deep paths, across 119,847 domains |
| Can its labels be trusted? | Phishing labels come from named feeds. Benign means "browsed", not verified |
| Is it safe to train on directly? | **No.** Month artefacts, path/query/www shortcuts and domain overlap all need handling |
| Is it independent of our data? | Only partly. 46,508 URLs overlap StealthPhisher and 2,508 overlap ours |

It is usable as a source of **benign URLs with realistic paths**, if every limit above is handled in preparation.

## 7. Proposed design for the experimental dataset (needs your approval)

| # | Decision | Rule |
| :--- | :--- | :--- |
| 1 | Cleaning | Apply section 4: no scheme, whitespace, entities decoded, normalised duplicates, conflicting labels removed |
| 2 | Query and fragment | Remove from every URL in this source before feature extraction |
| 3 | Months | Use only months with both classes (10 to 90% phishing), about 526,000 rows before cleaning, and report the rest as excluded |
| 4 | Domain split | New split by registrable domain. Each domain goes to training or evaluation only. Domains already in our current evaluation set stay out of training |
| 5 | Cap | A cap of 20 rows per domain, recorded in the report, to stop platforms dominating |
| 6 | Balance | Match the two classes on path-depth bins and `www.` presence by sampling, so these cannot separate classes alone |
| 7 | Mixed domains | Keep rows only where the URL itself is unambiguous. Do not decide a domain's label by hostname |
| 8 | Other sources | Do not add StealthPhisher phishing rows, because they largely duplicate this source |
| 9 | Provenance | Add a `source` column and keep the original dataset untouched |
| 10 | Output | A new file `ml/dataset/experimental_phreshphish.csv`, ignored by git, plus a counts report. Not used by the active model |

Expected result: roughly 300,000 usable rows after capping and balancing, to be confirmed by the script.

## 8. Not yet verified

- Whether benign labels hide malicious URLs. Browsing telemetry cannot be audited from the files.
- How the temporal artefacts were produced. The paper does not explain the months that are 100% one class.
- Whether training on the balanced subset actually helps. That is a Phase 4 and 5 question.

## 9. Housekeeping

| Item | State |
| :--- | :--- |
| Extracted URLs | `%TEMP%\phresh_full\phreshphish_urls.parquet`, local only, do not commit |
| Pilot file | `%TEMP%\phresh_pilot\train-000.parquet` (49.6 MB). Can be deleted |
| `pyarrow` | Installed in your Python environment only |
| Project files changed | None. This report is the only addition |
| Licence | CC BY 4.0, anti-phishing research only. Cite Dalton et al., 2025, arXiv 2507.10854 |
