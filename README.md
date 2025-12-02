# DNS Tunneling Detection Suite

Modernised end-to-end toolkit for collecting DNS traffic, extracting features,
training ML models and classifying tunneled queries.

## 🔎 Highlights
- `gui.py` provides a desktop GUI application for easy interaction with all features.
- `capture.py` replaces the legacy `dns_logger.py`, saving rich DNS metadata to `dns_log.csv`.
- Shared feature engineering lives in `features/dns_features.py` and is imported by every script.
- `predict.py` scores captured traffic with the persisted `best_dns_model.pkl` and writes `dns_predictions.csv`.
- `train_best.py`, `train_rf.py`, `train_all.py`, and `models/*.py` train/compare classifiers on labelled CSVs in `data/`.
- `cli.py` offers a one-command interface: `--capture`, `--predict`, or `--train`.

```
repo
├── gui.py               # desktop GUI application (Tkinter)
├── capture.py           # live packet capture → dns_log.csv
├── predict.py           # offline inference
├── train_best.py        # train RF/XGB/LR and persist the winner
├── train_all.py         # train every helper model and print stats
├── train_rf.py          # single-model trainer
├── cli.py               # convenience wrapper
├── features/
│   └── dns_features.py  # shared feature extraction + heuristics
├── models/              # helper trainers + selection utilities
├── data/
│   ├── normal_1500_queries.csv
│   └── suspicious_1500_queries.csv
├── dns_log.csv          # latest live capture (sample)
├── dns_predictions.csv  # latest predictions (sample)
├── best_dns_model.pkl   # persisted best model
└── requirements.txt
```

## ⚙️ Setup
```bash
git clone https://github.com/sharath-gowda-g/dns-tunnling-detection.git
cd dns-tunnling-detection
python -m venv .venv && .\.venv\Scripts\activate   # or source .venv/bin/activate
pip install -r requirements.txt
```

Npcap/WinPcap (Windows) or libpcap (Linux/macOS) plus Administrator/root
privileges are required for packet capture.

## 🚀 Usage

### Desktop GUI Application
```bash
python gui.py
```
Launch the Tkinter-based desktop GUI with:
- **Start Capture** button to begin DNS packet capture
- **Stop Capture** button (appears after starting capture)
- **Analyse** button to run predictions on captured data

The GUI provides a clean, user-friendly interface for all operations. Requires administrator privileges for capture functionality.

### Capture live DNS
```bash
python capture.py          # run as Administrator / sudo
```
The script auto-selects the active interface when possible, prints each query /
response, and appends rows to `dns_log.csv`.

### Classify captured traffic
```bash
python predict.py
```
Loads `best_dns_model.pkl`, extracts features from `dns_log.csv`, emits colored
console output, and saves human-friendly results to `dns_predictions.csv`.

### Train / refresh models
```bash
python train_best.py       # trains RF, XGBoost*, Logistic Regression
python train_rf.py         # only RandomForest
python train_all.py        # uses helper modules in models/
```
All trainers pull raw labelled data from `data/*.csv`, run the shared feature
pipeline, and persist the best-performing estimator to `best_dns_model.pkl`.
XGBoost is optional—if the package is missing the script automatically skips it.

### One-stop CLI
```bash
python cli.py --capture
python cli.py --predict
python cli.py --train
```

## 🧪 Data & Features
- `data/normal_1500_queries.csv` and `data/suspicious_1500_queries.csv` are
  included for offline experimentation.
- Feature vectors capture entropy, label statistics, uncommon TLD flags,
  tunneling keywords, base64-like labels, digit ratios, etc. See
  `features/dns_features.py` for the full set.

## 📄 License

MIT — see `LICENSE` (unchanged from the original repository).
