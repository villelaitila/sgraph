# Perform analysis on the graph itself
from __future__ import annotations

from sgraph import SElement, SElementAssociation, SGraph


class SGraphAnalysis:
    @staticmethod
    def generate_dynamic_dependencies(model: SGraph):
        """
        This function creates dynamic_* dependencies to all the implementations and subclasses.
        :param model:
        :return:
        """

        # Avoid creating duplicate associations with help of hash
        existing_associations_by_hash = {}
        stack = [model.rootNode]
        while stack:
            elem = stack.pop(0)
            for assoc in elem.outgoing:
                existing_associations_by_hash[assoc.getHashNum()] = assoc
            stack.extend(elem.children)

        new_deps: dict[int, SElementAssociation] = {}

        def getOverwrittenMembers(memberF: SElement, elemC: SElement):

            superclasses = [elemC]
            handled: set[SElement] = set()
            overwritten: list[SElement] = []
            while len(superclasses) > 0:
                superclass = superclasses.pop(0)
                handled.add(superclass)
                for association in superclass.incoming:
                    if association.deptype == 'inherits' or association.deptype == 'implements':
                        if association.fromElement in handled:
                            # Prevent endless loop (if the code has uncompilable inheritance cycle)
                            continue

                        superclasses.append(association.fromElement)
                        o = association.fromElement.getChildByName(memberF.name)
                        if o is not None:
                            overwritten.append(o)

            return overwritten

        def is_inherited_or_implemented(elem: SElement):
            for i in elem.incoming:
                if i.deptype == 'inherits' or i.deptype == 'implements':
                    return True

        def findAndCopyAsDynamicDeps(elemC: SElement):
            """
            for each class C that has incoming inherits/implements dependencies D,
              for each memberfunc F of C that has any incoming dependencies D2
                if F is overwritten in any C2 connected to C through D
                    for each overwritten F2 of F copy dependency D to connect D2.from to F2
            :param elemC:
            :return:
            """
            if elemC.typeEquals('class') and is_inherited_or_implemented(elemC):
                for f in elemC.children:
                    # TODO In future this might also apply to Property type of elements in some
                    # languages.
                    if f.typeEquals('function') and len(f.incoming) > 0:
                        for f2 in getOverwrittenMembers(f, elemC):
                            for func_call in f.incoming:
                                # Self dependencies e.g. recursive calls is not suitable base to
                                # generate dynamic deps
                                if (func_call.fromElement != func_call.toElement
                                        and func_call.fromElement != f2
                                        and not func_call.deptype.startswith('dynamic_')):
                                    dyn_type = 'dynamic_' + func_call.deptype
                                    dynamic_call = SElementAssociation(
                                        func_call.fromElement, f2, dyn_type, func_call.attrs)
                                    hash_num = dynamic_call.getHashNum()

                                    if hash_num not in existing_associations_by_hash:
                                        new_deps[hash_num] = dynamic_call

        stack = [model.rootNode]
        while stack:
            elem = stack.pop(0)
            findAndCopyAsDynamicDeps(elem)
            stack.extend(elem.children)

        for _, dep in sorted(new_deps.items()):
            dep.initElems()

    def merge_with_parent(self, child: SElement, parent: SElement):
        if not child.children:
            for association in child.outgoing:
                association.fromElement = parent
                parent.outgoing.append(association)
            for association in child.incoming:
                association.toElement = parent
                parent.incoming.append(association)
            parent.children.remove(child)
            parent.update_children_dict()
        else:
            for childschild in list(child.children):
                self.merge_with_parent(childschild, child)
            for association in child.outgoing:
                association.fromElement = parent
                parent.outgoing.append(association)
            for association in child.incoming:
                association.toElement = parent
                parent.incoming.append(association)
            parent.children.remove(child)
            parent.update_children_dict()

    def flatten_all_inside_by_type(self, graph: SGraph, etype: str):
        s = [graph.rootNode]
        while s:
            e = s.pop(0)
            if e.attrs.get('type') == etype:
                for child in list(e.children):
                    self.merge_with_parent(child, e)
            else:
                s.extend(e.children)
