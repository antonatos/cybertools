
# Requirements

python3, no extra dependencies required
# Usage

```
python3 snort2json.py [options]

Options:
  -h, --help            show this help message and exit
  -f FILE, --file=FILE  ruleset file
  -o FILE, --output=FILE
                        output file (optional)
```

# Example:

`python3 snort2json.py -f sample.rules` will print to stdout
`python3 snort2json.py -f sample.rules -o /tmp/converted_rules.json` will print to file `/tmp/converted_rules.json

