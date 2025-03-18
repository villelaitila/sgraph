from sgraph import SElement
from sgraph.compare.compareutils import tag_change_count
from sgraph.compare.similarityanalysis import elem_similarity


class RenameDetector:

    def identify_rename_pairs(self, a_elem: SElement, b_elem: SElement, renamed_elem__old_name: dict[SElement, str]):
        if len(a_elem.children) > 0 and len(b_elem.children) > 0:
            rename_pairs: list[tuple[SElement, SElement]] = []
            self.identify_renamed_children(a_elem.childrenDict, b_elem.childrenDict, rename_pairs)

            # set all renamed elements to have the updated name/params in the old model
            for p in rename_pairs:
                # Save the original name for later use
                renamed_elem__old_name[p[1]] = p[0].name

                if p[0].name == p[1].name:
                    raise Exception('Unexpected situation in rename detection, names equal.. ' +
                                    p[0].name)
                if p[0].name in p[0].parent.childrenDict:
                    p[0].parent.childrenDict.pop(p[0].name)
                else:
                    raise Exception('Unexpected situation in rename detection, childrenDict not in '
                                    'sync.. ' + p[0].getPath())
                p[0].name = p[1].name
                if p[0].name in p[0].parent.childrenDict:
                    raise Exception(
                        'Unexpected situation #2 in rename detection, childrenDict not in '
                        'sync.. ' + p[0].getPath())
                else:
                    p[0].parent.childrenDict[p[0].name] = p[0]

            for c_a in a_elem.children:
                c_b = b_elem.getChildByName(c_a.name)
                if c_b is not None:
                    self.identify_rename_pairs(c_a, c_b, renamed_elem__old_name)


    def identify_renamed_children(self, a_children: dict[str, SElement], b_children: dict[str, SElement],
                                  rename_pairs: list[tuple[SElement, SElement]]):
        """
        Identify renamed children
        :param a_children: children dict in A model
        :param b_children: children dict in B model
        :param rename_pairs: output list of renamed element pairs
        :return: None
        """
        # case 0:
        # identical sets, and names
        if a_children.keys() == b_children.keys():
            return

        # case 1:
        # 1 child in A and B, name is different
        a_set = set(a_children.keys())
        b_set = set(b_children.keys())
        if len(a_set) == len(b_set) == 1:
            a_elem = a_children[next(iter(a_set))]
            b_elem = b_children[next(iter(b_set))]
            # TODO this is good for rename cases but what if the actual element has moved under
            # some of the sub directories?
            # Should we check for the element type here also?
            rename_pairs.append((a_elem, b_elem))

        elif len(a_set) == len(b_set):
            # case k:
            # n children in A, n children in B
            unique_a = a_set.difference(b_set)
            unique_b = b_set.difference(a_set)
            if len(unique_a) == 1 and len(unique_b) == 1:
                a_elem = a_children[next(iter(unique_a))]
                b_elem = b_children[next(iter(unique_b))]
                # TODO this is good for rename cases but what if the actual element has moved under
                # Should we check for the element type here also?
                rename_pairs.append((a_elem, b_elem))
            elif len(unique_b) > 1:  # len(unique_a) == len(unique_a) also
                found_a = set()
                for a_name in unique_a:
                    a_elem = a_children[a_name]
                    matched_to = None
                    for b_name in unique_b:
                        b_elem = b_children[b_name]
                        if elem_similarity(a_elem, b_elem, 80, False):
                            # TODO: Improve this to seek for the best similarity points instead
                            # of stopping on first that has enough points.
                            rename_pairs.append((a_elem, b_elem))
                            matched_to = b_name
                            break
                    if matched_to is not None:
                        unique_b.remove(matched_to)
                        found_a.add(a_name)
                for f in found_a:
                    unique_a.remove(f)
                if len(unique_a) > 0:
                    self.match_with_points(a_children, b_children, rename_pairs, unique_a, unique_b)

        else:
            # case x:
            # n children in A, m children in B, maybe everything has restructured, maybe nothing
            # common
            unique_a = a_set.difference(b_set)
            unique_b = b_set.difference(a_set)

            if len(unique_a) == 0:
                # Only new elements
                pass

            elif len(unique_b) == 0:
                # Only removed elements
                pass

            else:
                self.match_with_points(a_children, b_children, rename_pairs, unique_a, unique_b)

    def match_with_points(self, a_children: dict[str, SElement], b_children: dict[str, SElement],
                          rename_pairs: list[tuple[SElement, SElement]],
                          unique_a: set[str], unique_b: set[str]):
        similarity_points = {}
        for a_name in sorted(unique_a):
            a_elem = a_children[a_name]
            for b_name in sorted(unique_b):
                b_elem = b_children[b_name]
                p = elem_similarity(a_elem, b_elem, 80, True)
                if p > 0:
                    similarity_points.setdefault(p, []).append((a_elem, b_elem))
        matched_a = set()
        matched_b = set()
        for p in sorted(similarity_points.keys(), reverse=True):
            if p >= 50:
                for pair in similarity_points[p]:
                    if pair[0] not in matched_a and pair[1] not in matched_b:
                        rename_pairs.append(pair)
                        matched_a.add(pair[0])
                        matched_b.add(pair[1])
                        b_elem = b_children[pair[1]]
                        b_elem.addAttribute("rename_detection_similarity_points", str(p))
            else:
                break

    def annotate_renamed_elems(self, model, renamed_elem__old_name):
        for renamed_elem, old_name in renamed_elem__old_name.items():
            compareElem = model.getElement(renamed_elem)
            compareElem.addAttribute('compare', 'changed')
            compareElem.addAttribute('renamed', 'true')
            compareElem.addAttribute('old_name', old_name)
            tag_change_count(compareElem, 1)

