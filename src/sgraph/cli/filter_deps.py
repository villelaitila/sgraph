import click
import re
import sys
"""
Use like this:

 python3 show_model.py |python3 filter_deps.py --pattern-from /NetflixOSS/External

 Or to show main element

 python3 show_model.py |grep -v /NetflixOSS/External |python3 filter_deps.py 
     --pattern-from /\\w+/\\w+ --pattern-to /\\w+/\\w+ --equation a!=b --deps-only True

"""


@click.command()
@click.option('--pattern-from', prompt='Pattern FROM', default='', help='Pattern for from element.')
@click.option('--pattern-to', prompt='Pattern TO', default='', help='Pattern for to element.')
@click.option('--equation', default='', help='Equation')
@click.option('--deps-only', default=False, help='Deps only')
@click.option('--debug', default=False, help='Debug')
def dofiltering(pattern_from, pattern_to, equation, deps_only, debug):
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

            print(depline)
        else:
            if not deps_only:
                print(line.strip())


if __name__ == '__main__':
    dofiltering()
