from __future__ import annotations

import copy
import functools
from typing import Callable, Sequence

from sgraph import SElement, SElementAssociation, SGraph
from sgraph.definitions import FilterAssocations, HaveAttributes


class ModelApi:
    egm: SGraph

    def __init__(
        self,
        filepath: str | None = None,
        model: SGraph | None = None,
    ):
        if filepath:
            self.model = SGraph.parse_xml_or_zipped_xml(filepath)
        elif model:
            self.model = model
        else:
            raise ValueError("Either filepath or model must be provided")

        self.egm = self.model

    def getElementByPath(self, filepath: str):
        return self.egm.findElementFromPath(filepath)

    @staticmethod
    def getChildrenByType(element: SElement, elemType: str):
        return [x for x in element.children if x.typeEquals(elemType)]

    def getElementsByName(self, name: str):
        matching: list[SElement] = []

        def recursiveTraverser(elem: SElement):
            if elem.name == name:
                matching.append(elem)
            for child in elem.children:
                recursiveTraverser(child)

        recursiveTraverser(self.egm.rootNode)
        return matching

    @staticmethod
    def getCalledFunctions(funcElem: SElement):
        functionCalls = [x for x in funcElem.outgoing if x.deptype == 'function_ref']
        return set(map(lambda x: x.toElement, functionCalls))

    @staticmethod
    def getCallingFunctions(funcElem: SElement):
        functionCalls = [x for x in funcElem.incoming if x.deptype == 'function_ref']
        return set(map(lambda x: x.fromElement, functionCalls))

    @staticmethod
    def getUsedElements(elem: SElement):
        associations = [x for x in elem.outgoing]
        return set(map(lambda x: x.toElement, associations))

    @staticmethod
    def getUserElements(elem: SElement):
        associations = [x for x in elem.incoming]
        return set(map(lambda x: x.fromElement, associations))

    def filter(self, filterfunc: Callable[[SElement], bool]):
        matched_elements: list[SElement] = []
        for c in self.egm.rootNode.children:
            self.__filter(c, filterfunc, matched_elements)
        return matched_elements

    def __filter(
        self,
        c: SElement,
        filterfunc: Callable[[SElement], bool],
        matched_elements: list[SElement],
    ):
        if filterfunc(c):
            matched_elements.append(c)
        for cc in c.children:
            self.__filter(cc, filterfunc, matched_elements)

    @staticmethod
    def query_dependencies_between(
            from_elems: list[SElement],
            to_elems: list[SElement],
            dep_filter: tuple[str, str, str] | None,
            prevent_self_deps: bool,
    ):
        found: list[SElementAssociation] = []
        for f in from_elems:
            s: list[SElement] = list()
            s.append(f)
            while len(s) > 0:
                elem = s.pop()
                for association in elem.outgoing:
                    if prevent_self_deps and ModelApi.matches_with_descendant(
                            association.toElement, tuple([f])):
                        pass
                    elif (association.toElement in to_elems
                          or ModelApi.matches_with_descendant(association.toElement, tuple(to_elems))):
                        ModelApi.add_if_matches(association, found, dep_filter)

                for c in elem.children:
                    s.append(c)
        return found

    @staticmethod
    def query_dependencies(
            elements: list[SElement],
            exclude: list[SElement] | None,
            dep_filter: tuple[str, str, str] | None,
            direction_is_out: bool,
            prevent_self_deps: bool,
    ):
        found: list[SElementAssociation] = []
        for f in elements:
            stack = [f]
            while len(stack) > 0:
                elem = stack.pop()
                if direction_is_out:
                    relations = elem.outgoing
                else:
                    relations = elem.incoming
                for association in relations:
                    if direction_is_out:
                        other_elem = association.toElement
                    else:
                        other_elem = association.fromElement

                    if exclude is None:
                        if not ModelApi.intra_file(association):
                            found.append(association)

                    elif prevent_self_deps and ModelApi.matches_with_descendant(other_elem, tuple([f])):
                        pass

                    elif other_elem not in exclude and not ModelApi.matches_with_descendant(
                            other_elem, tuple(exclude)):
                        ModelApi.add_if_matches(association, found, dep_filter)

                for c in elem.children:
                    stack.append(c)
        return found

    @staticmethod
    @functools.lru_cache(maxsize=None)
    def matches_with_descendant(elem: SElement, potential_ancestors_list: Sequence[SElement]):
        # NOTE: LRU CACHE NEEDS TO BE CLEARED IF THE MODEL IS CHANGED!
        for potential_ancestor in potential_ancestors_list:
            if elem.isDescendantOf(potential_ancestor):
                return True
        return False

    @staticmethod
    def intra_file(ea: SElementAssociation):
        return ea.fromElement.getAncestorOfType('file') == ea.toElement.getAncestorOfType('file')

    @staticmethod
    def not_a_sibling_ref(ea: SElementAssociation):
        return ea.fromElement.parent != ea.toElement.parent

    @staticmethod
    def add_if_matches(
            ea: SElementAssociation,
            found: list[SElementAssociation],
            dep_filter: tuple[str, str, str] | None,
    ):
        if dep_filter is not None:
            if dep_filter[1] == '==' and ea.check_attr(dep_filter[0], dep_filter[2]):
                if not ModelApi.intra_file(ea):
                    found.append(ea)
            elif dep_filter[1] == '!=' and not ea.check_attr(dep_filter[0], dep_filter[2]):
                if not ModelApi.intra_file(ea):
                    found.append(ea)
            elif dep_filter[1] == 'in' and isinstance(  # TODO: Clean up
                (attr := ea.attrs.get(dep_filter[0], '')), str) and dep_filter[2] in attr:
                if not ModelApi.intra_file(ea):
                    found.append(ea)
        else:
            if not ModelApi.intra_file(ea):
                found.append(ea)

    @staticmethod
    def filter_model(
        source_elem: SElement,
        source_graph: SGraph,
        filter_outgoing: FilterAssocations = FilterAssocations.Direct,
        filter_incoming: FilterAssocations = FilterAssocations.Direct,
        have_attributes: HaveAttributes = HaveAttributes.IncludeCopy,
    ):
        """
        Filter a sub graph from source_graph related to source elem.

        When executing filter_model for element e with "Ignore" mode, it ignores elements
        that are external to e.

        "Direct" mode changes this behavior: it picks also external elements associated
        with descendants of e. However, it is limited to direct assocations.

        "DirectAndIndirect" mode selects all directly and indirectly associated elements
        and their descendants.

        Traversal of "DirectAndIndirect" is not directed, i.e. it goes in undirected mode,
        leading into situations where you have the dependencies of your users also included.

        :param source_elem: element for filtering (descendants of it)
        :param source_graph: the overall graph to be filtered
        :param filter_outgoing: filtering mode for outgoing dependencies
        :param filter_incoming: filtering mode for incoming dependencies
        :param have_attributes: have attributes included, either as copy or reference, or ignore
        :return: new graph, that contains independent new SElement objects with same topology as
        in the source_graph
        """
        sub_graph = SGraph()
        _elem, _is_new = sub_graph.create_or_get_element(source_elem)
        stack = [source_elem]

        def is_descendant_of_source_elem(element: SElement):
            ancestor = element
            while ancestor.parent is not None:
                ancestor = ancestor.parent
                if ancestor == source_elem:
                    return True
            return False

        def create_assoc(x: SElement, other: SElement, is_outgoing: bool, ea: SElementAssociation):
            new_or_existing_referred_elem, this_is_new = sub_graph.create_or_get_element(x)

            if is_outgoing:
                SElementAssociation(other, new_or_existing_referred_elem, ea.deptype,
                                    ea.attrs).initElems()
            else:

                SElementAssociation(new_or_existing_referred_elem, other, ea.deptype,
                                    ea.attrs).initElems()

            return new_or_existing_referred_elem, this_is_new

        def handle_assocation(
            the_elem: SElement,
            ea: SElementAssociation,
            related_elem: SElement,
            filter_setting: FilterAssocations,
            is_outgoing: bool,
            assoc_stack: list[SElement],
        ):
            descendant_of_src = is_descendant_of_source_elem(related_elem)

            if not descendant_of_src and filter_setting == FilterAssocations.Ignore:
                return

            new_or_existing_referred_elem, this_new = create_assoc(related_elem, the_elem,
                                                                   is_outgoing, ea)

            if descendant_of_src:
                # No need to create descendants since those will be anyway created later as part of
                # the main iteration.
                return
            elif filter_setting == FilterAssocations.Direct:
                if this_new:
                    # Avoid creating descendants multiple times.
                    ModelApi.create_descendants(related_elem, new_or_existing_referred_elem, have_attributes)

            elif filter_setting == FilterAssocations.DirectAndIndirect:
                # Get all indirectly and directly used elements into the subgraph, including
                # their descendant elements.
                if related_elem not in handled:
                    assoc_stack.append(related_elem)

        handled: set[SElement] = set()
        # Traverse related elements from the source_graph using stack
        while stack:
            elem = stack.pop(0)
            handled.add(elem)

            the_elem, _is_new = sub_graph.create_or_get_element(elem)
            for association in elem.outgoing:
                handle_assocation(the_elem, association, association.toElement, filter_outgoing,
                                  True, stack)

            for association in elem.incoming:
                handle_assocation(the_elem, association, association.fromElement, filter_incoming,
                                  False, stack)

            stack.extend(elem.children)

        # Now that elements have been created, copy attribute data from the whole graph, via
        # traversal using two stacks. Earlier phases did not grab attributes on purpose, to make things
        # more simple.
        if have_attributes in (HaveAttributes.IncludeReference, HaveAttributes.IncludeCopy):
            stack = [sub_graph.rootNode]
            whole_graph_stack = [source_graph.rootNode]
            while stack:
                elem = stack.pop(0)
                corresponding_source_elem = whole_graph_stack.pop(0)

                if have_attributes == HaveAttributes.IncludeReference:
                    elem.attrs = corresponding_source_elem.attrs
                elif have_attributes == HaveAttributes.IncludeCopy:
                    elem.attrs = corresponding_source_elem.attrs.copy()

                for elem in elem.children:
                    stack.append(elem)
                    corresponding_elem = corresponding_source_elem.getChildByName(elem.name)
                    if corresponding_elem is not None:
                        whole_graph_stack.append(corresponding_elem)
                    else:
                        raise ValueError(
                            f"Element \"{elem.name}\" from sub graph not found in the whole graph"
                            f" but it should have been"
                        )
        elif have_attributes == HaveAttributes.Ignore:
            pass

        return sub_graph

    @staticmethod
    def create_descendants(
            related_elem: SElement,
            new_or_existing_referred_elem: SElement,
            have_attributes: HaveAttributes = HaveAttributes.Ignore,
    ):
        stack = [(related_elem, new_or_existing_referred_elem)]
        while stack:
            orig_and_new: tuple[SElement, SElement] = stack.pop(0)

            if orig_and_new[0].children:
                for child in orig_and_new[0].children:
                    new_child, is_new = orig_and_new[1].create_or_get_element(child.name)
                    if is_new:
                        if have_attributes == HaveAttributes.IncludeReference:
                            new_child.attrs = child.attrs
                        elif have_attributes == HaveAttributes.IncludeCopy:
                            new_child.attrs = copy.copy(child.attrs)
                        elif have_attributes == HaveAttributes.Ignore:
                            pass
                        stack.append((child, new_child))
                    stack.append((child, new_child))
