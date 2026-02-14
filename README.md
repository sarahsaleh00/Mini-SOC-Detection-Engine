# Mini SOC Detection Engine

A Python-based threat detection tool that analyzes security logs to identify brute force attacks, port scans, and web attacks.

> **Educational Project**: Built for learning Python and cybersecurity concepts. Not intended for production use.

## Features

- **Brute Force Detection** - Identifies repeated failed login attempts
- **Port Scan Detection** - Detects reconnaissance activity (in progress)
- **Web Attack Detection** - Finds SQL injection, XSS, and path traversal  attempts (in progress)

## Quick Start
```bash
# Run the detection engine
python soc_engine.py

# View the report
cat reports/alert_report.json
```

## Example Output
```json
{
  "brute_force_attempts": [
    {"ip": "192.168.1.100", "count": 7, "usernames": ["admin", "root"]}
  ]
}
```

## What I Learned

- Regex for log parsing
- Dictionary-based event counting
- Threat detection algorithms
- File I/O and JSON handling

## Project Structure
```
├── soc_engine.py          # Main engine
├── src/detections/        # Detection modules
├── logs/                  # Sample logs
└── reports/               # Output reports
```

---