from sgraph import SElement
from sgraph.compare.comparegraphattrs import CompareGraphAttrs


ignoredAttrs = {'days_since_modified'}

# Attrs that are always noise in time-windowed models (sliding window metrics).
# Useful as a preset for exclude_attrs parameter in ModelCompare.compare().
SLIDING_WINDOW_ATTRS = {
    'days_since_modified',
    'author_list_1', 'author_list_7', 'author_list_30', 'author_list_90',
    'author_list_180', 'author_list_365',
    'author_count_1', 'author_count_7', 'author_count_30', 'author_count_90',
    'author_count_180', 'author_count_365',
    'commit_count_1', 'commit_count_7', 'commit_count_30', 'commit_count_90',
    'commit_count_180', 'commit_count_365',
    'bug_fix_ratio_1', 'bug_fix_ratio_7', 'bug_fix_ratio_30',
    'bug_fix_ratio_90', 'bug_fix_ratio_180', 'bug_fix_ratio_365',
    'bug_fix_commit_count_1', 'bug_fix_commit_count_7', 'bug_fix_commit_count_30',
    'bug_fix_commit_count_90', 'bug_fix_commit_count_180', 'bug_fix_commit_count_365',
    'bug_count_1', 'bug_count_7', 'bug_count_30', 'bug_count_90',
    'bug_count_180', 'bug_count_365',
    'bug_list_1', 'bug_list_7', 'bug_list_30', 'bug_list_90',
    'bug_list_180', 'bug_list_365',
    'feature_count_1', 'feature_count_7', 'feature_count_30', 'feature_count_90',
    'feature_count_180', 'feature_count_365',
    'feature_list_1', 'feature_list_7', 'feature_list_30', 'feature_list_90',
    'feature_list_180', 'feature_list_365',
    'tech_debt_1', 'tech_debt_7', 'tech_debt_30', 'tech_debt_90',
    'tech_debt_180', 'tech_debt_365',
    'last_modified', 'latest_commits',
}


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
