from __future__ import annotations

from sgraph import SGraph


def pretty_print_model_stats(
    model: SGraph,
    stats: tuple[int, int, dict[str, int], float] | None = None,
    delta: tuple[int, int, dict[str, int], float] | None = None,
    optional_label: str = '',
):
    if stats is not None:
        pass  # using given
    else:
        stats = model.calculate_model_stats()

    def str_delta(num: float) -> str:
        if num < 0:
            return str(num)
        elif num > 0:
            return '+' + str(num)
        return '0'

    (dependenciesCount, nodesCount, depTypeCounts, depToElemRatio) = stats
    x = '\n MODEL STATS  (and change to previous) ' + optional_label
    x += '\n ==========='
    x += '\n Dependencies: ' + str(dependenciesCount)
    if delta:
        x += ' (' + str_delta(delta[0]) + ')'
    x += '    Elements: ' + str(nodesCount)
    if delta:
        x += ' (' + str_delta(delta[1]) + ')'
    if nodesCount != 0:
        x += '\n Dependencies to element ratio: ' + str(depToElemRatio) + ' %'
    else:
        x += '\n Dependencies to element ratio: N/A'
    if delta:
        x += ' (' + str_delta(delta[3]) + ')'

    x += '\n Dependencies breakdown: '
    keys = sorted(depTypeCounts.keys())
    for k in keys:
        x += str(depTypeCounts[k]) + 'x ' + k + ', '
    if x.endswith(', '):
        x = x[:-2]

    if delta:
        x += '\n                 Change: '
        keys = sorted(delta[2].keys())
        for k in keys:
            if delta[2][k] != 0 and k in depTypeCounts:
                x += str_delta(delta[2][k]) + ' ' + k + ', '
        x += '  No change: '
        for k in keys:
            if delta[2][k] == 0:
                x += k + ', '

        disappeared: str = ''
        appeared: str = ''
        for k in keys:
            if k not in depTypeCounts:
                if delta[2][k] < 0:
                    disappeared += str_delta(delta[2][k]) + ' ' + k + ', '
                elif delta[2][k] > 0:
                    appeared += str_delta(delta[2][k]) + ' ' + k + ', '

        if len(disappeared) > 0:
            x += '  Disappeared dependency types: '
            x += disappeared
        if x.endswith(', '):
            x = x[:-2]
        if len(appeared) > 0:
            x += '  New dependency types: '
            x += appeared
        if x.endswith(', '):
            x = x[:-2]

    return x + '\n'
