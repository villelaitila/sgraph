"""
Filter graph by removing some content of it using some of remove_* functions.
"""

from sgraph import SGraph


class SGraphFiltering:
    @staticmethod
    def remove_dependencies_by_deptypes(model: SGraph, dep_types_to_remove):
        """
        Remove dependencies
        :param model:
        :param dep_types_to_remove:
        :return:
        """
        dep_types_to_remove = set(dep_types_to_remove)

        def remove(elem):
            """
            :param elem:
            :return:
            """
            remove_eas = []
            for association in elem.outgoing:
                matched = False
                for d in dep_types_to_remove:
                    if association.deptype == d:
                        matched = True
                        break
                if matched:
                    remove_eas.append(association)

            for c in elem.children:
                remove(c)

        model.traverse(remove)

    @staticmethod
    def remove_dependencies_by_paths(model: SGraph, from_path: str, to_path: str):
        """
        Remove dependencies
        :param model: model
        :param from_path: from elemenet path
        :param to_path: to element path
        :return:
        """
        e1 = model.findElementFromPath(from_path)
        e2 = model.findElementFromPath(to_path)
        remove_assocs_list = []

        def remove_eas(elem):
            for association in elem.outgoing:

                if association.toElement == e2 or association.toElement.isDescendantOf(e2):
                    remove_assocs_list.append(association)

            for c in elem.children:
                remove_eas(c)

        if e1 is not None:
            remove_eas(e1)
            for r in remove_assocs_list:
                r.remove()

    @staticmethod
    def remove_dependencies_by_from_path(model: SGraph, from_path: str):
        """
        Remove dependencies
        :param model: model
        :param from_path: from element path
        :return:
        """
        from_elem = model.findElementFromPath(from_path)
        if from_elem is None:
            return

        remove_assocs_list = []

        def remove_eas(elem):
            for association in elem.outgoing:

                if association.toElement != from_elem or association.toElement.isDescendantOf(from_elem):
                    remove_assocs_list.append(association)

            for c in elem.children:
                remove_eas(c)

        if from_elem is not None:
            remove_eas(from_elem)
            for r in remove_assocs_list:
                r.remove()

    @staticmethod
    def remove_dependencies_by_to_path(model: SGraph, to_path: str):
        """
        Remove dependencies
        :param model: model
        :param to_path: to element path
        :return:
        """
        to_elem = model.findElementFromPath(to_path)
        if to_elem is None:
            return

        remove_assocs_list = []

        def remove_eas(elem):
            for association in elem.incoming:
                if (association.fromElement != to_elem or
                        association.fromElement.isDescendantOf(to_elem)):
                    remove_assocs_list.append(association)

            for c in elem.children:
                remove_eas(c)

        if to_elem is not None:
            remove_eas(to_elem)
            for r in remove_assocs_list:
                r.remove()
