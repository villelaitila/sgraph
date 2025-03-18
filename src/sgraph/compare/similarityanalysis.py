import difflib

import Levenshtein

from sgraph import SElement


def elem_similarity(elem_a, elem_b, points_level, return_points):
    points = 0

    if not elem_a.typeEquals(elem_b.getType()):
        # Type change always means a new element.
        if return_points:
            return 0
        else:
            return False
    else:
        points += 5

    def name_points(name_a, name_b):
        # Compare name similarity
        edit_distance = Levenshtein.distance(name_a, name_b)
        if edit_distance < 1:
            raise Exception('Invalid edit distance by stringmatcher')

        # Scale edit_distance to 0..65 with formula "n = 65 - 4e"
        name_similarity_points = max(0, 65 - 4 * edit_distance)
        # TODO Use also synonym database to identify cursory name changes that have big
        # edit_distance but mean the same.
        return name_similarity_points

    if elem_a.typeEquals('function'):
        pos_a = elem_a.name.find('(')
        pos_b = elem_b.name.find('(')
        if pos_a != -1 and pos_b != -1:
            # Name equals, just a param change
            name_a = elem_a.name[:pos_a]
            name_b = elem_b.name[:pos_b]
            if name_a == name_b:
                points += 65
                if points >= points_level:
                    if not return_points:
                        return True

            ratio = compare_parameters(elem_a, elem_b)
            points += ratio * 20
            if points >= points_level:
                if not return_points:
                    return True

            if name_a != name_b:
                # name and params are not equal, compare only name part
                points += name_points(name_a, name_b)

        elif pos_a != -1:
            pass  # no () in b --> so different that it does not make sense to compare name.
        elif pos_b != -1:
            pass  # no () in a --> so different that it does not make sense to compare name.
        else:
            # no () in function name, compare just name part
            points += name_points(elem_a.name, elem_b.name)

        # TODO Consider also the function source code and the relative position in the code
    else:
        # other types like class, file, dir, etc.
        points += name_points(elem_a.name, elem_b.name)

    if len(elem_a.outgoing) > 0 and len(elem_b.outgoing) > 0:
        related_a = list(map(lambda x: x.toElement.name, elem_a.outgoing))
        related_b = list(map(lambda x: x.toElement.name, elem_b.outgoing))
        if len(related_a) > 0 and len(related_b) > 0:
            sm = difflib.SequenceMatcher(None, related_a, related_b)
            points += 55 * sm.ratio()
            if points >= points_level:
                if not return_points:
                    return True
    if len(elem_a.outgoing) == 0 and len(elem_b.outgoing) == 0:
        points += 2
        if points >= points_level:
            if not return_points:
                return True

    if len(elem_a.incoming) > 0 and len(elem_b.incoming) > 0:
        related_a = list(map(lambda x: x.fromElement.name, elem_a.incoming))
        related_b = list(map(lambda x: x.fromElement.name, elem_b.incoming))
        if len(related_a) > 0 and len(related_b) > 0:
            sm = difflib.SequenceMatcher(None, related_a, related_b)
            points += 55 * sm.ratio()
            if points >= points_level:
                if not return_points:
                    return True
    if len(elem_a.incoming) == 0 and len(elem_b.incoming) == 0:
        points += 2
        if points >= points_level:
            if not return_points:
                return True

    if len(elem_a.children) == 0 and len(elem_b.children) == 0:
        points += 4
        if points >= points_level:
            if not return_points:
                return True

    if len(elem_a.children) > 0 and len(elem_b.children) > 0:
        related_a = list(map(lambda x: x.name, elem_a.children))
        related_b = list(map(lambda x: x.name, elem_b.children))
        if len(related_a) > 0 and len(related_b) > 0:
            sm = difflib.SequenceMatcher(None, related_b, related_b)
            points += 80 * sm.ratio()
            if points >= points_level:
                if not return_points:
                    return True

    if points >= points_level:
        if not return_points:
            return True

    # TODO What else to be used in comparison

    if return_points:
        return points
    else:
        return points > 90

def compare_parameters(elem_a: SElement, elem_b: SElement):
    """
    params is like "self;email;team_id;password;name"

    :param elem_a:
    :param elem_b:
    :return: ratio
    """
    if 'params' in elem_a.attrs and 'params' in elem_b.attrs:
        if elem_a.attrs['params'] == elem_b.attrs['params']:
            return 1
        else:
            params_a = elem_a.attrs['params']
            params_b = elem_b.attrs['params']
            if isinstance(params_a, str) and isinstance(params_b, str):
                sm = difflib.SequenceMatcher(None, params_a, params_b)
                return sm.ratio()
            else:
                raise Exception('Unexpected situation in compare_parameters, params not strings..')
    return 0

