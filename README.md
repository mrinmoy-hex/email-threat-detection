# Project structure:

```
src/
├── parser/          # .eml parsing → structured Email object
│   └── email_parser.py
├── headers/         # SPF/DKIM/DMARC, Received chain
│   └── header_analyzer.py
├── content/         # NLP/phishing-language scoring
│   └── content_analyzer.py
├── urls/            # link extraction, redirect chasing, domain age
│   └── url_analyzer.py
├── intel/           # IP geolocation, WHOIS, reputation APIs
│   ├── geolocation.py
│   └── reputation.py
├── scoring/         # aggregates signals → verdict + explanation
│   └── threat_scorer.py
├── report/          # forensic report generation
│   └── report_builder.py
└── main.py          # orchestrates the pipeline

```