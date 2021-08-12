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
        :return:
        """
        dep_types_to_remove = set(dep_types_to_remove)

        def remove(elem):
            """
            :param elem:
            :return:
            """
            remove_eas = []
            for ea in elem.outgoing:
                matched = False
                for d in dep_types_to_remove:
                    if ea.deptype == d:
                        matched = True
                        break
                if matched:
                    remove_eas.append(ea)

            for c in elem.children:
                remove(c)

        model.traverse(remove)

    @staticmethod
    def remove_dependencies_by_paths(model: SGraph, from_path, to_path):
        """
        Remove dependencies
        :param model:
        :return:
        """
        e1 = model.getElementFromPath(from_path)
        e2 = model.getElementFromPath(to_path)
        remove_eas_list = []

        def remove_eas(elem):
            for ea in elem.outgoing:

                if ea.toElement == e2 or ea.toElement.isDescendantOf(e2):
                    remove_eas_list.append(ea)

            for c in elem.children:
                remove_eas(c)

        if e1 is not None:
            remove_eas(e1)
            for r in remove_eas_list:
                r.remove()

    @staticmethod
    def remove_dependencies_by_from_path(model: SGraph, from_path):
        """
        Remove dependencies
        :param model:
        :return:
        """
        from_elem = model.getElementFromPath(from_path)
        if from_elem is None:
            return

        remove_eas_list = []

        def remove_eas(elem):
            for ea in elem.outgoing:

                if ea.toElement != from_elem or ea.toElement.isDescendantOf(from_elem):
                    remove_eas_list.append(ea)

            for c in elem.children:
                remove_eas(c)

        if from_elem is not None:
            remove_eas(from_elem)
            for r in remove_eas_list:
                r.remove()

    @staticmethod
    def remove_dependencies_by_to_path(model: SGraph, to_path):
        """
        Remove dependencies
        :param model:
        :return:
        """
        to_elem = model.getElementFromPath(to_path)
        if to_elem is None:
            return

        remove_eas_list = []

        def remove_eas(elem):
            for ea in elem.incoming:

                if ea.fromElement != to_elem or ea.fromElement.isDescendantOf(to_elem):
                    remove_eas_list.append(ea)

            for c in elem.children:
                remove_eas(c)

        if to_elem is not None:
            remove_eas(to_elem)
            for r in remove_eas_list:
                r.remove()
