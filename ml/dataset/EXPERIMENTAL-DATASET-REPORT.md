# Experimental PhreshPhish Dataset: Counts Report

Produced by `ml/prepare_phreshphish.py` from the URL table fetched by `ml/fetch_phreshphish_urls.py`.

- **Output (git-ignored, local only):** `ml/dataset/experimental_phreshphish.csv`
- **Machine-readable counts:** `ml/dataset/experimental_phreshphish_report.json`
- **Not used by the active model.** The v3 model, the original dataset, the extractor, the API and the extension are unchanged.

Source: PhreshPhish, Dalton et al., 2025, arXiv 2507.10854, CC BY 4.0, for anti-phishing research only. Please cite it when using this data.

## 1. Accepted, rejected and deduplicated

| Step | Rows before | Rows after | Removed | Note |
| :--- | ---: | ---: | ---: | :--- |
| Input | 666,315 | 666,315 | 0 | All 77 files |
| Cleaning | 666,315 | 660,556 | 5,759 | 5,741 no scheme, 17 whitespace, 1 unparseable |
| Months with both classes | 660,556 | 520,451 | 140,105 | 8 months kept |
| URLs seen with both labels | 520,451 | 520,440 | 11 | 3 keys removed entirely |
| Normalised duplicates | 520,440 | 509,014 | 11,426 | First kept by date |
| Already in our current dataset | 509,014 | 508,314 | 700 | Normalised match |
| Cap of 20 rows per site and label | 508,314 | **329,140** | 179,174 | 411 sites hold both labels |

**Final: 329,140 rows.** The balanced subset holds 113,320 of them.

### Months

| Kept | Excluded (rows, phishing share) |
| :--- | :--- |
| 2024-08, 2024-09, 2024-10, 2025-06, 2025-07, 2025-08, 2025-09, 2025-10 | 2024-07 (53,552, 99.7%), 2024-11 (15,585, 100%), 2024-12 (7,868, 100%), 2025-01 (23,003, 100%), 2025-02 (9,324, 100%), 2025-03 (5,678, 100%), 2025-04 (2,800, 100%), 2025-11 (21,278, 90.2%), 2025-12 (1,017, 0%) |

## 2. Split

Every site (registrable domain, or full hostname on shared hosting) is in exactly one split.

| Split | Rows | Benign | Phishing | Sites |
| :--- | ---: | ---: | ---: | ---: |
| Train | 262,821 | 184,941 | 77,880 | 150,709 |
| Eval | 66,319 | 46,474 | 19,845 | 37,973 |

Rules used for assignment:

- Sites that are in the current dataset's **test** split stay in eval (3,600 rows).
- Sites that are in the current dataset's **training** split stay in train (13,831 rows).
- All other sites are assigned by a fixed hash, 20% to eval.

This keeps the current model's training domains out of the new evaluation set.

## 3. Balanced subset

Within each combination of path depth, path length and `www.` prefix, both classes were sampled to the same size.

| Split | Rows | Benign | Phishing |
| :--- | ---: | ---: | ---: |
| Train | 90,568 | 45,284 | 45,284 |
| Eval | 22,752 | 11,376 | 11,376 |

| Property | All rows: benign | All rows: phishing | Balanced: benign | Balanced: phishing |
| :--- | ---: | ---: | ---: | ---: |
| URLs with a path | 89.0% | 43.3% | 70.4% | 70.4% |
| Deep path (2+ segments) | 66.0% | 20.1% | 34.6% | 34.6% |
| Starts with `www.` | 56.8% | 9.7% | 16.7% | 16.7% |

### Strongest single-feature signals (ROC-AUC, 0.5 means none)

| Subset | Top features |
| :--- | :--- |
| All rows | `path_length` 0.792, `path_depth` 0.783, `url_length` 0.697, `hostname_entropy` 0.697, `on_shared_hosting` 0.659 |
| Balanced | `digit_count` 0.652, `hostname_entropy` 0.638, `hostname_hyphen_count` 0.632, `dot_count` 0.631, `hostname_length` 0.626 |

The path and `www.` shortcuts are gone in the balanced subset. What remains is host-level structure, which is what the model is meant to learn.

## 4. Validation of the output

Checked independently of the preparation script:

| Check | Result |
| :--- | :--- |
| Sites in both train and eval | 0 |
| URLs containing `?` or `#` | 0 |
| URLs not starting with http or https | 0 |
| URLs containing whitespace | 0 |
| Normalised duplicates | 0 |
| Overlap with current dataset (exact and normalised) | 0 |
| New train rows on current test sites | 0 |
| New eval rows on current train sites | 0 |
| Maximum rows per site and label | 20 |
| Existing 32-feature extractor | 0 failures on 143,320 rows |

## 5. Remaining limitations

| Limitation | Effect |
| :--- | :--- |
| Benign means "browsed", not verified safe | Some malicious URLs may be in the benign class. Cannot be audited here |
| Query strings removed from all rows | The query features carry no signal from this data, and real URLs at prediction time have queries |
| `on_shared_hosting` remains informative (AUC about 0.62) | Phishing is concentrated on hosting platforms. This is a real pattern, but also a property of this dataset |
| Only 8 of 17 months used | Reduces temporal coverage and campaign diversity |
| 4,827 rows (1.5%) are on sites that hold both labels | Flagged in the `mixed_site` column |
| Cap of 20 removes 35% of rows | Phishing from a few platforms is heavily reduced, so the balanced subset is dominated by long-tail sites |
| Balanced subset equalises path shape on purpose | The model cannot use path shape from this data, even where it is a genuine signal |
| Phishing partly overlaps StealthPhisher | Not used here, so no duplication, but results are not independent of that dataset |
| Collected 2024 to 2025 | Patterns may differ from today's |

## 6. How to reproduce

```bash
pip install pyarrow
python ml/fetch_phreshphish_urls.py --out ml/source/phreshphish_urls.parquet
python ml/prepare_phreshphish.py --input ml/source/phreshphish_urls.parquet
```

Fetch transfers about 27 MB and takes about 5 minutes. Preparation takes a few minutes. Neither trains a model.

## 7. What this enables next (not started)

| Step | Description |
| :--- | :--- |
| Candidate model | Train a separate model under a new filename on the train split, with and without the balanced restriction, using the unchanged 32-feature extractor |
| Fair comparison | Score v3 and the candidate on exactly the eval-split sites |
| Targeted checks | Legitimate sites with paths, phishing on unseen domains, shared-hosting sites, and the original held-out set |
| Decision | Keep v3 unless the candidate clearly wins on those checks |
