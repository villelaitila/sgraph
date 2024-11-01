from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sgraph import SElement

from sgraph.algorithms.selementutils import lowest_common_ancestor


class SElementAssociation:
    __slots__ = 'deptype', 'fromElement', 'toElement', 'attrs'

    fromElement: SElement
    toElement: SElement
    deptype: str
    attrs: dict[str, str | int | list[str]]

    @staticmethod
    def create_unique_element_association(
        from_element: SElement,
        to_element: SElement,
        dependency_type: str,
        dependency_attributes: dict[str, str | int | list[str]],
    ) -> tuple["SElementAssociation", bool]:
        """Create an association between two elements if there already does not
        exist a similar association.
        The association is considered to be similar if to_element has an
        incoming association with the same type and the same fromElement.
        :param: from_element the elemenet that is the starting point of the
            association
        :param: to_element the element that is the ending point of the
            association
        :param: deptype the type of the association
        :param: depattrs attributes for the associtaion
        :returns: Return tuple of the existing
            or new element and a boolean indicating if a new element was
            created (true if new was created, false otherwise)"""
        def filter_existing(incoming: "SElementAssociation"):
            from_element_matches = incoming.fromElement == from_element
            if dependency_type:
                return dependency_type == incoming.deptype and \
                    from_element_matches
            else:
                return from_element_matches

        filtered_associations = filter(filter_existing, to_element.incoming)
        existing_associations = list(filtered_associations)

        # Do not create association if the same association already exists
        if len(existing_associations) > 0:
            # Combine attributes to the existing association
            existing_associations[0].attrs.update(dependency_attributes)
            # return {'existingOrNewAssociation': existing_associations[0], 'isNew': False}
            return existing_associations[0], False

        new_association = SElementAssociation(from_element, to_element, dependency_type,
                                              dependency_attributes)
        new_association.initElems()
        return new_association, True

    def __init__(
        self,
        fr: SElement,
        to: SElement,
        deptype: str,
        depattrs: dict[str, str | int | list[str]] | None = None,
    ):
        self.deptype = deptype

        # Good to have this decommented when testing new analyzers:
        # if fr is not None and fr == to:
        #    sys.stderr.write('Self loop #1\n')
        self.fromElement = fr
        self.toElement = to
        if depattrs is not None:
            self.attrs = depattrs
        else:
            self.attrs = {}

    def getHashNum(self):
        result = 29
        result = 31 * result + hash(self.fromElement)
        result = 31 * result + hash(self.toElement)
        result = 31 * result + hash(self.deptype)
        result = 31 * result + self.calculateCompareStatus()
        return result

    def calculateCompareStatus(self):
        compare = self.attrs.get('compare', None)
        if compare == 'added':
            return 1
        elif compare == 'removed':
            return 2
        elif compare == 'changed':
            return 3
        return 0

    def setAttrMap(self, attrmap: dict[str, str | int | list[str]]):
        self.attrs = attrmap

    def getFromPath(self):
        return self.fromElement.getPath()

    def getToPath(self):
        return self.toElement.getPath()

    def getType(self):
        return self.deptype

    def getAttributes(self):
        return self.attrs

    def initElems(self):
        self.fromElement.outgoing.append(self)
        self.toElement.incoming.append(self)

    def remove(self):
        self.fromElement.outgoing.remove(self)
        self.toElement.incoming.remove(self)

    def addAttribute(self, attr_name: str, attr_val: str | int | list[str]):
        self.attrs[attr_name] = attr_val

    def get_dependency_length(self):
        if self.fromElement == self.toElement:
            return 0

        lca = lowest_common_ancestor(self.fromElement, self.toElement)

        def levels_between(e: SElement, ancestor: SElement):
            steps = 0
            next_anc = e.parent
            while next_anc is not None and next_anc.parent is not None:
                steps += 1
                if ancestor == next_anc:
                    break
                next_anc = next_anc.parent
            return steps

        if lca is None:
            raise ValueError("Lowest common ancestor not found")

        dependency_length = levels_between(self.fromElement, lca) + \
            levels_between(self.toElement, lca)

        return dependency_length

    def initOrExtendListAttribute(self, a: str, v: str):
        attr = self.attrs.get(a, None)
        if attr is None:
            self.attrs[a] = [v]
        elif isinstance(attr, list) and v not in attr:
            attr.append(v)

    def __str__(self):
        attrs = str(sorted(filter(lambda x: x[0] != 'type', self.attrs.items())))
        return self.fromElement.getPath() + ' -' + self.getType() + '-> ' \
            + self.toElement.getPath() + ' ' + attrs

    __repr__ = __str__

    @staticmethod
    def match_ea_from_other_sgraph(ea: "SElementAssociation", ea_list: list["SElementAssociation"]):
        for candidate in ea_list:
            if candidate.toElement.name != ea.toElement.name:
                continue
            if candidate.deptype != ea.deptype:
                continue
            if not candidate.toElement.elem_location_matches(ea.toElement):
                continue
            return candidate

    def check_attr(self, attr: str, val: str | list[str]):
        if attr == 'type' and self.deptype == val:
            return True
        elif self.attrs.get(attr, None) == val:
            return True
        return False
