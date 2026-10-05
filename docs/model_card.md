# Model card — HTTP traffic classifier

Everything on this page was produced by `ml/train.py` against
`data/http_dataset.csv` (22,360 rows, 37 features, seed 42). The raw numbers
are in `data/model_metrics.json`.

The point of this document is to state plainly what the scores do and do not
mean, because an earlier version of this project reported "high accuracy"
obtained by scoring a model against labels it had generated from its own
features. That number was circular and the code that produced it is gone.

## Dataset

| Label | Rows | Produced by |
|---|---|---|
| `benign` | 4,616 | Browsing and API traffic from 5 browser UAs and 8 non-browser clients |
| `dirb` | 4,614 | real `dirb` binary |
| `ffuf` | 4,614 | real `ffuf` binary |
| `nikto` | 4,555 | real `nikto` binary |
| `nmap` | 2,491 | real `nmap` NSE http-* scripts |
| `sqlmap` | 1,470 | real `sqlmap` binary |

Total: 22,360 rows, 17,744 attack (79.4%).

### How labels are assigned

`ml/generate_dataset.py` starts the HTTP logger, generates benign traffic, then
runs each attack tool against it one at a time. Because the logger only appends,
the line count after each stage marks the exact boundary between tools, so each
request is labelled by **provenance** — which program sent it — and never by
inspecting its contents.

This is the single most important property of the dataset. A label that is a
function of the features makes every downstream score meaningless.

Regenerate it with:

```bash
python3 ml/generate_dataset.py --out data/http_dataset.csv
```

Requires `sqlmap`, `nikto`, `nmap`, `ffuf` and `dirb` on `PATH`. Missing tools
are skipped with a warning rather than silently substituted.

### Known dataset limitations

These are real weaknesses, not caveats:

* **Synthetic benign traffic.** Benign requests come from a Python thread pool
  with a fixed path list. Real traffic has a much wider path and parameter
  distribution.
* **Loopback only.** Everything is generated against `127.0.0.1`. The
  destination IP never varies, and there are no multi-session or
  concurrent-connection patterns.
* **Five tools, five signatures.** Each tool has a distinctive user agent and
  request rhythm. That is realistic — real scanners are fingerprintable — but
  it means a random split can score well for the wrong reason. See below.
* **No TLS.** Port 80 plaintext only.
* **Heavy class imbalance,** 79.4% attack. Handled with `class_weight="balanced"`.

## Random forest — supervised

`RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced")`

Held-out stratified 20% test set, never seen during fitting:

| Metric | Score |
|---|---|
| Accuracy | 0.9982 |
| Precision | 0.9992 |
| Recall | 0.9986 |
| F1 | 0.9989 |
| ROC-AUC | 0.9997 |

5-fold stratified cross-validation over the full dataset: accuracy 0.9985,
F1 0.9990, ROC-AUC 1.0000.

**Read this as:** the model separates *these five tools' traffic* from *this
generator's benign traffic* almost perfectly.

**Do not read this as:** "99.8% attack detection". See the next section.

## Leave-one-tool-out — the honest generalisation test

The random split cannot reveal fingerprint memorisation: each scanner appears in
both halves, so the model can recognise it from its user agent alone. Holding out
an entire tool removes that shortcut. Each fold trains on benign + four tools and
tests only on the unseen fifth.

| Held-out tool | Test rows | Recall | Precision | F1 |
|---|---|---|---|---|
| `nmap` | 2,491 | 0.8868 | 1.0000 | 0.9400 |
| `dirb` | 4,614 | 0.7850 | 1.0000 | 0.8796 |
| `ffuf` | 4,614 | 0.2547 | 1.0000 | 0.4059 |
| `nikto` | 4,555 | 0.0683 | 1.0000 | 0.1278 |
| `sqlmap` | 1,470 | **0.0000** | 0.0000 | 0.0000 |

**Mean recall: 0.3989.**

This is the number that matters, and it is roughly a fortieth of the held-out
F1. The gap is the whole story:

* The near-perfect random-split score is substantially fingerprint memorisation.
* Precision stays at 1.0 in every fold — when this model fires, it is right.
  The problem is recall, not false alarms.
* `sqlmap` is **completely** missed. Its requests are short, parameterised GETs
  whose distinguishing features live in the query string, and nothing in the
  other four tools' traffic teaches the model to recognise that shape.
* `nikto` and `ffuf` are largely missed for the same reason at lower severity.

**Conclusion:** the feature set captures *volume and path-probing* behaviour
well, and fails on *injection-payload* behaviour it has never seen. A model
trained on this dataset should not be deployed as a general web-attack detector.

## Isolation forest — unsupervised

`IsolationForest(contamination=0.1)`, fitted on features only, never shown a label.
The scores below are the labels being held against it as an external judgement.

| Metric | Score |
|---|---|
| Flagged | 2,236 of 22,360 (10.0%) |
| Precision | 0.8394 |
| Recall | 0.1058 |
| F1 | 0.1879 |
| Accuracy | 0.2743 |

**Accuracy 0.2743 is the expected outcome, not a bug.** The dataset is 79.4%
attack. Predicting every row as benign scores 0.206; the isolation forest beats
that by correctly flagging 1,877 attacks, but misses 84% of them.

When 79% of traffic is hostile, "rare" and "malicious" are simply not the same
thing, and an unsupervised model cannot know better from features alone. This is
exactly why the classifier above is supervised.

## Feature importance

`data/feature_importance.png`, Gini importance from the supervised model. The
ranking is dominated by request shape (`sensitive_path_hits`, `sqli_token_hits`,
`status_4xx`, `traversal_hits`) rather than by timestamp or IP — a sensible
ordering, though the leave-one-tool-out result shows these features do not
transfer to unseen tools.

## Intended use

* Research and education about traffic classification.
* Demonstrating the difference between supervised and unsupervised detection.
* Showing why a random train/test split overstates performance on fingerprinted
  data.

## Out of scope

* **Not** a production WAF or IDS.
* **Not** validated against CIC-IDS2017 or any public benchmark — the labels here
  are generated, not imported, so the numbers are not comparable to published
  results on those datasets.
* **Not** robust to novel tooling. See the leave-one-tool-out table.

## Reproducing

```bash
python3 ml/train.py --data data/http_dataset.csv --seed 42
```

Runs the supervised model, 5-fold cross-validation, leave-one-tool-out, the
isolation forest, and writes `data/model_metrics.json` plus the importance PNG.
Roughly 25 seconds on 8 cores. Pass `--contamination` to change the expected
anomaly rate.