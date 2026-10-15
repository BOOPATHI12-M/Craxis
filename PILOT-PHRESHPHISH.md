# PhreshPhish Pilot Report

Scope: one file, `data/train-000.parquet` (49.6 MB), reading only the `url`, `label` and `date` columns. The HTML column was never read. No training happened and no project file was changed.

The downloaded file is outside the project at `%TEMP%\phresh_pilot\train-000.parquet`.

## 1. Result in one paragraph

PhreshPhish does supply what StealthPhisher lacked: benign URLs with real, deep paths from many different domains. But it carries its own set of shortcuts, in the opposite direction. Used naively it would teach "has a deep path means benign" and "no query means benign". Those can be handled in data preparation, so the source is usable, but only with the preprocessing in section 5.

## 2. What the file is

| Item | Value |
| :--- | :--- |
| Rows | 1,000 (594 benign, 406 phishing) |
| Columns | `sha256`, `url`, `label`, `target`, `date`, `lang`, `lang_score`, `html` |
| Label values | `benign` and `phish` |
| Dates | 2024-07-04 to 2025-09-08 |
| Missing URLs | 0 |
| Why 50 MB for 1,000 rows | The HTML column is large. The three columns we need are tiny |

This is a 1,000-row sample from one file, so every figure below is an indication, not a measurement of the full 666,000 rows.

## 3. What the URLs look like

| Property | Benign (594) | Phishing (406) |
| :--- | ---: | ---: |
| Distinct registrable domains | 485 | 213 |
| URLs with a path | **92.8%** | 58.4% |
| Root only (no path) | 7.2% | 41.6% |
| Two or more path segments | 74.1% | n/a |
| Median path length | **30** | 3 |
| URLs with a query | **0.0%** | 7.6% |
| URLs with a fragment | 0.0% | 0.2% |
| HTTPS | 97.6% | 88.9% |
| Starts with `www.` | **57.2%** | 4.7% |
| On shared hosting | 0.3% | 32.5% |
| IP-address host | 0.0% | 0.25% |
| Top 10 domains' share | 14.1% | **42.6%** |
| Median URL length | 54 | 40 |

Benign examples (real paths, truncated):

```
https://en.wikipedia.org/wiki/Academy_Stadium
https://www.alzheimers.org.uk/about-dementia/types-dementia/symptoms-vascular-dementia
https://www.royalcanin.com/us/cats/products/vet-products/urinary-so-3901
https://ca.finance.yahoo.com/currencies/
```

## 4. Quality checks

| Check | Result |
| :--- | :--- |
| Exact duplicate URLs | 0 |
| Normalised duplicates | 0 groups |
| Conflicting labels on the same URL | 0 |
| Domains labelled both ways | 1 (`office.com`, 2 rows: an Outlook page as benign and a Forms page as phishing) |
| Existing 32-feature extractor | 0 exceptions and 0 NaN on all 1,000 rows (20,000 requested, 1,000 available) |
| HTML entities in URLs | Present (`&amp;` in a phishing URL). Needs decoding |
| Benign rows with **no scheme** | 12 (2%), 0 phishing rows |

### 4.1 Strongest single-feature signals

ROC-AUC of one feature alone, where 0.5 means no signal:

| Feature | AUC | Direction in this sample |
| :--- | ---: | :--- |
| `path_length` | 0.786 | Longer path means benign |
| `path_depth` | 0.768 | Deeper path means benign |
| `hostname_length` | 0.729 | Longer hostname means phishing |
| `hostname_entropy` | 0.726 | Higher entropy means phishing |
| `hostname_hyphen_count` | 0.681 | More hyphens means phishing |
| `on_shared_hosting` | 0.661 | Shared hosting means phishing |
| `url_length` | 0.656 | |

## 5. Problems found and the planned handling

| # | Problem | Why it matters | Planned handling |
| :--- | :--- | :--- | :--- |
| 1 | **Queries only exist in phishing** (0.0% vs 7.6%) | The query features would perfectly flag phishing, but only because the benign side was stripped | Remove queries and fragments from **every** row before feature extraction |
| 2 | **Path shortcut is reversed**: benign has deep paths, phishing mostly root | The model could learn "deep path means benign" and miss phishing on compromised sites | Balance path-length bins across the two classes when combining with our existing phishing data (which has paths in about 55 to 64% of rows) |
| 3 | **`www.` prefix**: 57% benign vs 5% phishing | A formatting habit is not evidence of safety | Stratify or weight by `www` presence. Do not add or remove `www.` artificially |
| 4 | **12 benign rows have no scheme** | The `https` feature would read as 0 for benign rows only | Exclude them. The real scheme is unknown, so it will not be guessed |
| 5 | **Phishing concentration** (top 10 domains hold 42.6%) | Model learns a few platforms | Cap rows per domain |
| 6 | **Shared hosting** nearly absent from benign (0.3%) | Any shared-hosting site looks phishing | Keep our existing synthetic benign shared-hosting share and report it as an assumption. Do not claim real data for it |
| 7 | **HTML entities** | `&amp;` changes length and special-character counts | Decode entities |
| 8 | **Small sample** | One file of 1,000 rows | Re-measure all of the above on the full set before building anything |

## 6. Overlap with our existing data

| Check | Result |
| :--- | ---: |
| Exact URLs also in our current dataset | 6 |
| Pilot domains also in our current dataset | 83 of 801 |
| Pilot rows on those domains | 185 of 1,000 |
| Pilot domains also in StealthPhisher | 171 |

Overlap is moderate. Evaluation domains must be chosen so that none appears in training from any source.

## 7. What this does and does not establish

**Established:**
- Real benign URLs with deep paths exist in this source and are diverse.
- The existing extractor handles them without errors.
- No duplicate or conflicting labels in this sample.

**Not established:**
- That benign labels are correct. They mean "browsed", and the sample cannot show hidden malicious URLs.
- That the full dataset behaves like this one file.
- That training on it improves anything.
- How many of the roughly 666,000 rows survive cleaning.

## 8. Recommendation

Proceed, with care, to the next step.

Proposed next step (needs your approval):

1. Read **only `url`, `label` and `date`** from all train and test files using column reads over HTTP, so the HTML is never transferred. Test it on one more file first and report the transfer size and time before running the rest.
2. Apply the handling in section 5.
3. Re-measure every figure in this report on the full set.
4. Stop and report before any dataset is built or any model is trained.

Expected size is small compared with the 36.6 GB repository, but I will measure it on one file before committing to the full read.

## 9. Housekeeping

| Item | State |
| :--- | :--- |
| `pyarrow` | Installed in your Python environment to read Parquet. Not added to project requirements |
| Downloaded file | `%TEMP%\phresh_pilot\train-000.parquet`, 49.6 MB. Delete anytime |
| Project files changed | None. This report is the only addition |
