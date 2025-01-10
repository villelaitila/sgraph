import sys
from typing import Optional

from sgraph import SGraph, SElement, SElementAssociation

Level = int


def generalize_model(model: SGraph, level_to_generalize: int = 3,
                     have_element_attrs: bool = True, have_assoc_attrs: bool = False) -> SGraph:
    """
    Generalize a model up to a certain level. This means that all elements that are at a level higher than LEVEL
    are removed from the model. All dependencies that are connected to these elements are also re-connected to the
    closest element that is at level LEVEL or lower.

    This is useful for e.g. detailed and large source code models, where you want to see the high-level structure
    of the code, but not all the details.

    :param model: The model to generalize
    :param level_to_generalize: The level to generalize the model to, default value 3
    :param have_element_attrs: If True, the attributes of the elements are copied to the generalized model
    :param have_assoc_attrs: If True, the attributes of the associations are copied to the generalized model
    :return: The generalized model
    """
    generalized_model = SGraph()
    old_to_old = {}

    def recurse_elements(elem_to_recurse: SElement, current_level: int,
                         last_element_on_desired_level: Optional[SElement]):
        if current_level == level_to_generalize:
            last_element_on_desired_level = elem_to_recurse
        elif current_level > level_to_generalize:
            old_to_old[elem_to_recurse] = last_element_on_desired_level

        for child_of_elem in elem_to_recurse.children:
            recurse_elements(child_of_elem, current_level + 1, last_element_on_desired_level)

    for root_child in model.rootNode.children:
        recurse_elements(root_child, 1, None)


    old_to_new = copy_model_and_build_map(level_to_generalize, generalized_model, model, have_element_attrs)

    # Now we have the generalized_model and the original model similar up to the level LEVEL,
    #  But no dependencies.

    stack = [(model.rootNode, 1)]
    new_model_stack = [generalized_model.rootNode]
    while stack:
        elem, level = stack.pop(0)
        new_model_elem_or_none = new_model_stack.pop(0)

        for dependency in elem.outgoing:

            if new_model_elem_or_none:
                ea_from = new_model_elem_or_none
            else:
                ea_from_2 = old_to_old[dependency.fromElement] if dependency.fromElement in old_to_old\
                    else dependency.fromElement
                ea_from = old_to_new[ea_from_2]

            if dependency.toElement in old_to_new:
                ea_to = old_to_new[dependency.toElement]
            else:
                if dependency.toElement not in old_to_old:
                    raise Exception('Invalid situation')
                o = old_to_old[dependency.toElement] if dependency.toElement in old_to_old else dependency.toElement
                if o not in old_to_new:
                    raise Exception('Invalid situation')
                ea_to = old_to_new[o]

            if ea_to is None:
                raise Exception('Invalid situation')
            if ea_from is None:
                raise Exception('Invalid situation')
            if ea_to == ea_from:
                pass
            else:
                new_dependency = SElementAssociation(ea_from, ea_to, dependency.deptype)
                new_dependency.initElems()
                if have_assoc_attrs:
                    new_dependency.attrs = dependency.attrs

        for child in elem.children:
            stack.append((child, level + 1))
            if new_model_elem_or_none:
                new_child_or_none = new_model_elem_or_none.getChildByName(child.name)
            else:
                new_child_or_none = None
            new_model_stack.append(new_child_or_none)

    # Clean duplicate dependencies:
    new_model_stack = [generalized_model.rootNode]
    while new_model_stack:
        elem = new_model_stack.pop(0)

        if elem.outgoing:
            if len(elem.outgoing) > 1:
                eas_per_target = {}
                for ea in elem.outgoing:
                    eas_per_target.setdefault(ea.toElement, []).append(ea)
                new_eas = []
                for target, eas in eas_per_target.items():
                    dep_types = sorted(set([ea.deptype for ea in eas]))
                    if len(dep_types) > 1:
                        new_ea = SElementAssociation(elem, target, 'mixed')
                        new_ea.attrs['all_dep_types'] = dep_types
                        new_ea.attrs['dep_count'] = len(eas)
                    else:
                        new_ea = SElementAssociation(elem, target, dep_types.pop())
                        new_ea.attrs['all_dep_types'] = dep_types
                        new_ea.attrs['dep_count'] = len(eas)
                    new_eas.append(new_ea)
                for ea in list(elem.outgoing):
                    ea.remove()
                for new_ea in new_eas:
                    new_ea.initElems()
            else:
                elem.outgoing[0].attrs['all_dep_types'] = [elem.outgoing[0].deptype]
                elem.outgoing[0].attrs['dep_count'] = 1

        for child in elem.children:
            new_model_stack.append(child)

    return generalized_model


def copy_model_and_build_map(max_level: int, generalized_model: SGraph, model: SGraph, have_element_attrs: bool):
    stack = [(model.rootNode, 1)]
    new_model_stack = [generalized_model.rootNode]
    # Iterate all elements of the model, going from the root node to the leaves.
    # For each element, keep also track of the level of depth in the tree (e.g. root is 0, children of root are 1, etc.)
    old_to_new = {}
    while stack:
        elem, level = stack.pop(0)
        new_model_elem = new_model_stack.pop(0)

        if level > max_level:
            continue

        for child in elem.children:
            stack.append((child, level + 1))

            new_child = SElement(new_model_elem, child.name)
            old_to_new[child] = new_child
            if have_element_attrs:
                new_child.attrs = child.attrs
            new_model_stack.append(new_child)
    if not old_to_new:
        raise Exception('Internal error in the generalizer')
    return old_to_new


def main():
    # For adhoc testing and usage
    model = SGraph.parse_xml_or_zipped_xml(sys.argv[1])
    generalized_model = generalize_model(model, int(sys.argv[3]))
    generalized_model.to_xml(sys.argv[2])
    print(open(sys.argv[2]).read())


if __name__ == '__main__':
    main()


