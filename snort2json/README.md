
# Introduction

A converter of Snort 2.9 rules to a to a more manageable JSON format

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

`python3 snort2json.py -f sample.rules -o /tmp/converted_rules.json` will print to file `/tmp/converted_rules.json`

For example, the Snort rule:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Traceroute ipopts"; ipopts:rr; itype:0; reference:arachnids,238; classtype:misc-activity; sid:2100455; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
```

will be converted to:

```json
[
    {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": "$EXTERNAL_NET",
        "src_port": "any",
        "dst_ip": "$HOME_NET",
        "dst_port": "any",
        "options": [
            {
                "key": "msg",
                "value": "\"GPL ICMP_INFO Traceroute ipopts\""
            },
            {
                "key": "ipopts",
                "value": "rr"
            },
            {
                "key": "itype",
                "value": "0"
            },
            {
                "key": "reference",
                "value": "arachnids,238"
            },
            {
                "key": "classtype",
                "value": "misc-activity"
            },
            {
                "key": "sid",
                "value": "2100455"
            },
            {
                "key": "rev",
                "value": "8"
            },
            {
                "key": "metadata",
                "value": "created_at 2010_09_23, updated_at 2010_09_23"
            }
        ]
    }
]
```

