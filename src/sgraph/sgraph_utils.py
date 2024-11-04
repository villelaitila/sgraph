from .sgraph import SElementAssociation


# This file cannot have much type annotations because of circular deps.


def addEA(deptype: str, info: str | None, id1: str, id2: str, model) -> SElementAssociation:
    e1 = None
    if not id1.startswith('generate dependency'):
        e1 = model.createOrGetElementFromPath(id1)
    e2 = None
    if not id2.startswith('generate dependency'):
        e2 = model.createOrGetElementFromPath(id2)

    if e1 is None or e2 is None:
        raise ValueError(
            f"Could not find elements for dependency {deptype} between {id1} and {id2}")

    if info is not None and len(info) > 0:
        new_ea = SElementAssociation(e1, e2, deptype, {'detail': info})
    else:
        new_ea = SElementAssociation(e1, e2, deptype, {})
    new_ea.initElems()
    return new_ea


def find_assocs_between(e_orig, e, elems: list) -> set[tuple]:
    elem_tuples: set[tuple] = set()
    for out in e.outgoing:
        for elem in elems:
            if out.toElement.isDescendantOf(elem):
                elem_tuples.add((e_orig, elem))
    for child in e.children:
        elem_tuples.update(find_assocs_between(e_orig, child, elems))
    return elem_tuples


class ParsingIntentionallyAborted(Exception):
    pass
