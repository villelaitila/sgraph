from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sgraph import SElement


def lowest_common_ancestor(a: SElement, b: SElement):
    # Note: This can be optimized with better algorithm
    #  https://en.wikipedia.org/wiki/Lowest_common_ancestor
    fromAncs = list(reversed(a.getAncestors()))
    toAncs = list(reversed(b.getAncestors()))
    lca = None
    for i in range(len(fromAncs)):
        if len(toAncs) > i:
            if fromAncs[i] == toAncs[i]:
                lca = fromAncs[i]
            else:
                break
    return lca
