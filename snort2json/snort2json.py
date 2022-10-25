from optparse import OptionParser
from collections import OrderedDict, defaultdict
import re
import json

class Rule:

    def __init__(self, rule_str):
        self.rule_str = rule_str

    def set_header(self, action: str, protocol: str, src_ip: str, src_port: str, direction: str, dst_ip: str, dst_port: str):
        self.action = action
        self.protocol = protocol

        self.src_ip = src_ip 
        self.src_port = src_port 

        self.direction = direction

        self.dst_ip = dst_ip 
        self.dst_port = dst_port 

    def set_options(self, options: list):
        self.options = options

    def get_option(self, key) -> list:
        return [d for d in self.options if d['key'] == key]

    def convert(self):
        raise NotImplementedError()

    def to_dict(self):
        return {'action': self.action, 'protocol': self. protocol, 
            'src_ip': self.src_ip, 'src_port': self.src_port, 
            'dst_ip': self.dst_ip, 'dst_port': self.dst_port,
            'options': self.options}

    def __str__(self):
        return self.action + " " +  self.protocol + " " + self.src_ip + " " + self.src_port + " " + self.direction + " " + self.dst_ip + " " + self.dst_port +  ":: " + str(self.options)

def parse_options(options: str) -> list:
    parsed_options = []

    assert options.startswith('(') and options.endswith(')')

    options = options[1:-1].strip()

    while True:
        total_len = len(options)

        if total_len == 0:
            break

        i = options.find(';', 0)
        while options[i - 1] == '\\':
            i = options.find(';', i + 1)

        option = options[:i]
        s_index = option.find(':')

        keyword, value = (option[:s_index], option[s_index+1:].strip()) if s_index > 0 else (option, None)

        parsed_options.append({'key': keyword, 'value': value})

        options = options[i+1:].strip()

    return parsed_options 

def parse_rule(line: str) -> Rule:
    tokens = re.split('\s+', line, 7)

    rule = Rule(line)
    rule.set_header(tokens[0], tokens[1], tokens[2], tokens[3], tokens[4], tokens[5], tokens[6])

    options = tokens[7]
    opts = parse_options(options)
    rule.set_options(opts)

    return rule

def parse_file(filename, output_filename):

    rules_array = []

    with open(filename) as f:
        for line in f:
            line = line.strip()

            if len(line) == 0 or line.startswith('#'):
                continue

            rule = parse_rule(line)
            rules_array.append(rule.to_dict())

    if output_filename:
        with open(output_filename, 'w') as f:
            json.dump(rules_array, f, indent=4*' ')
    else:
        print(json.dumps(rules_array, indent=4*' '))

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="filename",
                  help="ruleset file", metavar="FILE")
    parser.add_option("-o", "--output", dest="output",
                  help="output file (optional)", metavar="FILE")
    
    (options, args) = parser.parse_args()

    if not options.filename:
        print("No snort ruleset file provided")
        parser.print_help()
        exit(1)

    parse_file(options.filename, options.output)
