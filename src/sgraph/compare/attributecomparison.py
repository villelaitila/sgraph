import sys

from sgraph.compare.comparegraphattrs import CompareGraphAttrs
from sgraph.compare.compareutils import add_up_change_count, get_non_null_attr, ignoredAttrs, get_delim


def compare_attrs(attributes1, attributes2, outmap, type1, type2):
    attrs = set()

    def isListAttribute(attrName):
        return attrName == 'license' or '_list' in attrName

    # Severe changes like hash change and license change are treated as "real" changes that
    # add up into change count metrics.

    c = CompareGraphAttrs.CHANGED_ATTRIBUTES
    if type1 is not None and type2 is not None:
        if type1 != type2:
            outmap[c + '_type'] = type1 + ';' + type2
    elif type1 is None and type2 is not None:
        outmap[c + '_type'] = '__;' + type2
    elif type1 is not None:
        outmap[c + '_type'] = type1 + ';--'

    if attributes1 is None:
        for attr in attributes2.keys():
            outmap[c + '_' + attr] = '--;' + get_non_null_attr(attributes2, attr)
        return ';'.join(attributes2.keys()), add_up_change_count(attributes2)
    if attributes2 is None:
        for k, v in attributes1.items():
            outmap[c + '_' + k] = v + ';--'
        return ';'.join(attributes1.keys()), add_up_change_count(attributes1)

    keys1 = set(attributes1.keys())
    keys2 = set(attributes2.keys())

    intersection = set(keys1)
    intersection.intersection(keys2)
    intersection -= ignoredAttrs

    # TODO: Similar logic needed as implemented in desktop
    # attributes need special handling here depending on the kind of attribute

    for attrName in intersection:
        val1 = attributes1.get(attrName)
        val2 = attributes2.get(attrName)
        if not val1 or not val2:
            attrs.add(attrName)
            outmap[c + '_' + attrName] = "new attribute"
            continue

        if val1 == val2:
            pass  # Identical
        else:
            if not isListAttribute(attrName) or (isinstance(val1, str) and len(val1) != len(val2)):
                outmap[c + '_' +
                       attrName] = (str(attributes1[attrName]) + get_delim(val1, val2) +
                                    str(attributes2[attrName]))
                attrs.add(attrName)
            elif isListAttribute(attrName):
                items1 = list()
                if isinstance(val1, float):
                    sys.stderr.write('Problematic value for a list attr {}, val={}\n'.format(
                        attrName, val1))
                else:
                    items1 = list(val1.split(';'))
                items2 = list()
                if isinstance(val2, float):
                    pass
                else:
                    items2 = list(val2.split(';'))
                items1.sort()
                items2.sort()

                if items1 != items2:
                    outmap[c + '_' +
                           attrName] = (attributes1[attrName] + get_delim(val1, val2) +
                                        attributes2[attrName])
                    attrs.add(attrName)

    keys1 = filter(lambda x: x not in intersection, keys1)
    for attribute_in_a in keys1:
        val = attributes1[attribute_in_a]
        if val != '':
            outmap[c + '_' + attribute_in_a] = '{};--'.format(val)
            attrs.add(attribute_in_a)

    keys2 = filter(lambda x: x not in intersection, keys2)
    for attribute_in_b in keys2:
        val = attributes2[attribute_in_b]
        if val != '':
            outmap[c + '_' + attribute_in_b] = '--;{}'.format(val)
            attrs.add(attribute_in_b)

    return ';'.join(attrs), add_up_change_count(attrs)
