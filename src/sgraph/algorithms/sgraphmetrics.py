from sgraph import SElement
from sgraph.sgraph_utils import find_assocs_between


class SGraphMetrics:

    def __init__(self):
        pass

    def calculate_association_density(
        self,
        graph,
        elempath: str,
        detail_level: int,
        external_elem: SElement | None = None,
    ):
        elems: list[SElement] = []

        def traverse_until(elem: SElement, current_level: int, the_detail_level: int):
            if current_level >= the_detail_level and external_elem != elem:
                elems.append(elem)
            elif external_elem != elem:
                for c in elem.children:
                    traverse_until(c, current_level + 1, the_detail_level)
                if not elem.children:
                    elems.append(elem)

        if elempath == '/':
            # "global" situation
            e = graph.rootNode
            traverse_until(e, 0, detail_level)
            for c in e.children:
                traverse_until(c, 1, detail_level)
        else:
            e = graph.findElementFromPath(elempath)
            if e is not None:
                traverse_until(e, e.getLevel(), detail_level)

        if len(elems) == 0:
            return 0

        assocs_between: set[tuple[SElement, SElement]] = set()
        for e in elems:
            assocs = find_assocs_between(e, e, elems)
            if assocs:
                assocs_between.update(assocs)

        return len(assocs_between) / len(elems), len(assocs_between), len(elems)
