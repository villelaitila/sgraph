from __future__ import annotations

import argparse
import re
import sys

doc_message = """
Use like this:

 python3 show_model.py |python3 filter_deps.py --pattern-from /NetflixOSS/External

 Or to show main element

 python3 show_model.py |grep -v /NetflixOSS/External |python3 filter_deps.py --pattern-from /\\w+/\\w+
     --pattern-to /\\w+/\\w+ --equation a!=b --deps-only

"""


def dofiltering(pattern_from: str, pattern_to: str, equation: str, deps_only: bool, debug: bool):
    """Filter dependencies"""
    pfrom = None
    pto = None
    if pattern_from != '':
        pfrom = re.compile('^' + pattern_from)
    if pattern_to != '':
        pto = re.compile('^' + pattern_to)

    for line in sys.stdin:
        if ':' in line and not line.startswith('@'):
            depline = line.strip()
            splitted = depline.split(':')
            frompart = splitted[0]
            topart = splitted[1]
            from_m = None
            to_m = None
            if pfrom:
                from_m = pfrom.search(frompart)
                if from_m is None:
                    if debug:
                        sys.stderr.write('Skip line, Could not match from=' + pattern_from +
                                         ' to ' + frompart + '\n')
                    continue
            if pto:
                to_m = pto.search(topart)
                if to_m is None:
                    if debug:
                        sys.stderr.write('Skip line, Could not match to=' + pattern_from + ' to ' +
                                         frompart + '\n')
                    continue

            if equation != '':
                if equation == 'a==b' or equation == 'a!=b':
                    if from_m is None or to_m is None:
                        if debug:
                            sys.stderr.write('Skip line, compare: missing match objects.\n')
                        continue

                    if equation == 'a==b' and from_m.group(0) == to_m.group(0):
                        pass
                    elif equation == 'a!=b' and from_m.group(0) != to_m.group(0):
                        pass
                    else:
                        if debug:
                            sys.stderr.write('Skip line, Condition failed\n')
                        continue
                else:
                    if debug:
                        sys.stderr.write('Skip line, Unknown equation\n')
                    continue

            print(depline)
        else:
            if not deps_only:
                print(line.strip())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Filter dependencies\n' + doc_message)
    parser.add_argument('--pattern-from', default='', help='Pattern for from element.')
    parser.add_argument('--pattern-to', default='', help='Pattern for to element.')
    parser.add_argument('--equation', default='', help='Equation')
    parser.add_argument('--deps-only', action='store_true', help='Deps only')
    parser.add_argument('--debug', action='store_true', help='Debug')

    args = parser.parse_args()
    dofiltering(args.pattern_from, args.pattern_to, args.equation, args.deps_only, args.debug)
