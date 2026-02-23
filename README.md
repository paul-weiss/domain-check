# domain-check

Checks domain name availability across multiple TLDs using RDAP, with a WHOIS fallback for TLDs that don't support RDAP (`.io`, `.co`).

## Requirements

```
pip install requests
```

## Usage

```bash
# Check words from domain_words.json against default TLDs (com, ai, app, io, co)
python3 domain_check.py

# Use a different JSON words file
python3 domain_check.py --words=mywords.json

# Load words from a plain text file (one word per line)
python3 domain_check.py words.txt

# Specify custom TLDs
python3 domain_check.py words.txt --tlds=com,ai,app,io
```

## Word list format

`domain_words.json` supports three keys:

```json
{
  "words": ["verifai", "provai"],
  "prefixes": ["true", "real"],
  "roots": ["check", "lens"]
}
```

- **words** — checked as-is
- **prefixes** + **roots** — combined into every `prefix+root` pair (e.g. `truecheck`, `truelens`, `realcheck`, `reallens`)

## Output

Available domains are highlighted in the live output. A CSV file (`domain_results_<timestamp>.csv`) is saved after each run containing all results (available, taken, unknown).

## Supported TLDs

| TLD | Protocol |
|-----|----------|
| .com | RDAP |
| .net | RDAP |
| .org | RDAP |
| .ai  | RDAP |
| .app | RDAP |
| .dev | RDAP |
| .tech | RDAP |
| .io  | WHOIS fallback |
| .co  | WHOIS fallback |
| .me  | WHOIS fallback |
