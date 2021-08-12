# Perform analysis on the graph itself
from sgraph import SElementAssociation
from sgraph import SGraph


class SGraphAnalysis:
    @staticmethod
    def generate_dynamic_dependencies(model: SGraph):
        """
        This function creates dynamic_* dependencies to all the implementations and subclasses.
        :param model:
        :return:
        """
        new_deps = {}

        def getOverwrittenMembers(memberF, elemC):

            superclasses = [elemC]
            handled = set()
            overwritten = []
            while len(superclasses) > 0:
                superclass = superclasses.pop(0)
                handled.add(superclass)
                for ea in superclass.incoming:
                    if ea.deptype == 'inherits' or ea.deptype == 'implements':
                        if ea.fromElement in handled:
                            # Prevent endless loop (if the code has uncompilable inheritance cycle)
                            continue

                        superclasses.append(ea.fromElement)
                        o = ea.fromElement.getChildByName(memberF.name)
                        if o is not None:
                            overwritten.append(o)

            return overwritten

        def is_inherited_or_implemented(elem):
            for i in elem.incoming:
                if i.deptype == 'inherits' or i.deptype == 'implements':
                    return True

        def findAndCopyAsDynamicDeps(elemC):
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
                                if func_call.fromElement != func_call.toElement:
                                    # Do not create new self dependencies
                                    if func_call.fromElement != f2:
                                        dynamic_call = SElementAssociation(
                                            func_call.fromElement, f2,
                                            'dynamic_' + func_call.deptype, func_call.attrs)
                                        hash_num = dynamic_call.getHashNum()
                                        new_deps[hash_num] = dynamic_call

            else:
                for c in elemC.children:
                    findAndCopyAsDynamicDeps(c)

        model.traverse(findAndCopyAsDynamicDeps)

        for _, dep in sorted(new_deps.items()):
            dep.initElems()

    def merge_with_parent(self, child, parent):
        if not child.children:
            for ea in child.outgoing:
                ea.fromElement = parent
                parent.outgoing.append(ea)
            for ea in child.incoming:
                ea.toElement = parent
                parent.incoming.append(ea)
            parent.children.remove(child)
            parent.update_children_dict()
        else:
            for childschild in list(child.children):
                self.merge_with_parent(childschild, child)
            for ea in child.outgoing:
                ea.fromElement = parent
                parent.outgoing.append(ea)
            for ea in child.incoming:
                ea.toElement = parent
                parent.incoming.append(ea)
            parent.children.remove(child)
            parent.update_children_dict()

    def flatten_all_inside_by_type(self, graph, etype):
        s = [graph.rootNode]
        while s:
            e = s.pop(0)
            if e.attrs.get('type') == etype:
                for child in list(e.children):
                    self.merge_with_parent(child, e)
            else:
                s.extend(e.children)
