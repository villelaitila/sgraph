from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from sgraph import SElement

from sgraph.algorithms.selementutils import lowest_common_ancestor

class SElementAssociation:
    __slots__ = 'deptype', 'fromElement', 'toElement', 'attrs'

    @staticmethod
    def create_unique_element_association(
            from_element, to_element, dependency_type, dependency_attributes):
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
        :returns: {SElement, boolean} Return a dict containing the existing
            or new element and a boolean indicating if a new element was
            created (true if new was created, false otherwise)"""
        def filter_existing(incoming):
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
            return {'existingOrNewAssociation': existing_associations[0],
                    'isNew': False}

        new_association = SElementAssociation(
            from_element, to_element, dependency_type, dependency_attributes)
        new_association.initElems()
        return {'existingOrNewAssociation': new_association, 'isNew': True}

    def __init__(self, fr, to, deptype, depattrs=None):
        self.deptype = deptype

        # Good to have this decommented when testing new analyzers:
        # if fr is not None and fr == to:
        #    sys.stderr.write('Self loop #1\n')
        self.fromElement: 'SElement' = fr
        self.toElement: 'SElement' = to
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

    def setAttrMap(self, attrmap):
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
        self.fromElement = None
        self.toElement.incoming.remove(self)
        self.toElement = None

    def addAttribute(self, attr_name, attr_val):
        self.attrs[attr_name] = attr_val

    def get_dependency_length(self):
        if self.fromElement == self.toElement:
            return 0

        lca = lowest_common_ancestor(self.fromElement, self.toElement)

        def levels_between(e, ancestor):
            steps = 0
            next_anc = e.parent
            while next_anc is not None and next_anc.parent is not None:
                steps += 1
                if ancestor == next_anc:
                    return steps
                next_anc = next_anc.parent

        dependency_length = levels_between(self.fromElement, lca) + \
            levels_between(self.toElement, lca)

        return dependency_length

    def initOrExtendListAttribute(self, a, v):
        if a not in self.attrs:
            self.attrs[a] = [v]
        elif v not in self.attrs[a]:
            self.attrs[a].append(v)

    def __str__(self):
        attrs = str(sorted(filter(lambda x: x[0] != 'type', self.attrs.items())))
        return self.fromElement.getPath() + ' -' + self.getType() + '-> ' \
               + self.toElement.getPath() + ' ' + attrs

    __repr__ = __str__

    @staticmethod
    def match_ea_from_other_sgraph(ea, ea_list):
        for candidate in ea_list:
            if candidate.toElement.name != ea.toElement.name:
                continue
            if candidate.deptype != ea.deptype:
                continue
            if not candidate.toElement.elem_location_matches(ea.toElement):
                continue
            return candidate

    def check_attr(self, attr, val):
        if attr == 'type' and self.deptype == val:
            return True
        elif self.attrs.get(attr, None) == val:
            return True
        return False
