def lowest_common_ancestor(a, b):
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
