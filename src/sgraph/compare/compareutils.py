from sgraph import SElement
from sgraph.compare.comparegraphattrs import CompareGraphAttrs


ignoredAttrs = {'days_since_modified'}


def tag_change_count(compareElement: SElement, changecount: int):
    if changecount > 0:
        if compareElement.attrs is not None and CompareGraphAttrs.CHANGE_COUNT in \
                compareElement.attrs:
            val = compareElement.attrs[CompareGraphAttrs.CHANGE_COUNT]
            if isinstance(val, int):
                compareElement.attrs[CompareGraphAttrs.CHANGE_COUNT] = changecount + val
            else:
                raise Exception(
                    'Unexpected situation in tagChangeCount, CHANGE_COUNT not int..')
        else:
            if compareElement.attrs is None:
                compareElement.attrs = {}
            compareElement.attrs[CompareGraphAttrs.CHANGE_COUNT] = changecount


def get_non_null_attr(attributes2: dict[str, str], attr: str):
    if attr in attributes2:
        if attributes2[attr] is None:
            return ''
        return attributes2[attr]
    return ''


def debunk_uniqueness(user: SElement, used: SElement, side: str):
    for x in user.outgoing:
        if x.toElement == used:
            if '_only_in' not in x.attrs:
                return True
            elif x.attrs['_only_in'] == side:
                return True
        elif x.toElement.isDescendantOf(used):
            if '_only_in' not in x.attrs:
                return True
            elif x.attrs['_only_in'] == side:
                return True
    for c in user.children:
        result = debunk_uniqueness(c, used, side)
        if result:
            return True
    return False


def add_up_change_count(attrs: set[str]):
    change_count = 0
    if 'hash' in attrs:
        change_count += 1
    if 'license' in attrs:
        change_count += 1
    return change_count


def get_delim(val1, val2):
    delim = ';'
    if isinstance(val1, str) and isinstance(val2, str):
        if ';' in val1 or ';' in val2:
            delim = ';;'
    return delim
