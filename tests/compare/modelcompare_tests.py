from sgraph import SGraph, SElement, SElementAssociation, ModelApi
from sgraph.compare.attributecomparison import compare_attrs
from sgraph.compare.modelcompare import ModelCompare
from sgraph.compare.compareutils import ignoredAttrs, SLIDING_WINDOW_ATTRS


def test_compareModels():
    model1 = SGraph.parse_deps_lines('/Servers/Linux/redhat/RHEL6\n'
                                    '/Servers/Windows/WinServer/Win2012 RCE:/Servers/Windows/WinServer/Win2016 RS\n'
                                    '/Servers/Windows/WinServer/Win2012 RCE:/Servers/Linux/redhat/RHEL6\n'
                                    '/Servers/Windows:/Servers/Solaris/SOO\n'
                                    '/Servers/Windows/WinServer/Win1233:/Servers/Solaris\n'.splitlines())
    model_api = ModelApi(model=model1)
    model2 = model_api.filter_model(model1.rootNode, model1)
    rename_element = model2.findElementFromPath('/Servers/Linux/redhat/RHEL6')

    rename_element.rename('RHEL7')

    model_compare = ModelCompare()
    compare_output = model_compare.compareModels(model1, model2)
    print(compare_output.to_deps(None))


def test_compare_attrs_intersection_correctness():
    """Verify that intersection is computed correctly (regression for set.intersection() bug)."""
    attrs1 = {'hash': 'abc', 'loc': '100', 'only_in_a': 'yes'}
    attrs2 = {'hash': 'def', 'loc': '100', 'only_in_b': 'yes'}
    outmap = {}

    changed_attrs, change_count = compare_attrs(attrs1, attrs2, outmap, 'file', 'file')

    # 'hash' changed → should appear in changed_attrs
    assert 'hash' in changed_attrs
    # 'loc' identical → should NOT appear
    assert 'loc' not in changed_attrs
    # 'only_in_a' should be reported as removed (val;--)
    assert '_attr_diff_only_in_a' in outmap
    assert outmap['_attr_diff_only_in_a'].endswith(';--')
    # 'only_in_b' should be reported as added (--;val)
    assert '_attr_diff_only_in_b' in outmap
    assert outmap['_attr_diff_only_in_b'].startswith('--;')


def test_compare_attrs_ignored_attrs_excluded_from_only_in():
    """Ignored attrs should not appear in 'only in A/B' diffs."""
    attrs1 = {'hash': 'abc', 'days_since_modified': '10'}
    attrs2 = {'hash': 'abc'}
    outmap = {}

    changed_attrs, _ = compare_attrs(attrs1, attrs2, outmap, 'file', 'file')

    # days_since_modified is in ignoredAttrs and only in attrs1 → should be excluded
    assert 'days_since_modified' not in changed_attrs
    assert '_attr_diff_days_since_modified' not in outmap


def test_exclude_attrs_in_compareModels():
    """exclude_attrs should suppress specified attributes from comparison output."""
    model1 = SGraph(SElement(None, ''))
    e1 = model1.createOrGetElementFromPath('/proj/src/file.py')
    e1.addAttribute('hash', 'aaa')
    e1.addAttribute('commit_count_30', '5')

    model2 = SGraph(SElement(None, ''))
    e2 = model2.createOrGetElementFromPath('/proj/src/file.py')
    e2.addAttribute('hash', 'bbb')
    e2.addAttribute('commit_count_30', '15')

    mc = ModelCompare()

    # Without exclude_attrs: both hash and commit_count_30 should show as changed
    result_full = mc.compareModels(model1, model2)
    file_elem = result_full.findElementFromPath('/proj/src/file.py')
    full_diff = file_elem.attrs.get('_attr_diff', '')
    assert 'hash' in full_diff
    assert 'commit_count_30' in full_diff

    # With exclude_attrs: commit_count_30 should be suppressed
    result_filtered = mc.compareModels(model1, model2, exclude_attrs={'commit_count_30'})
    file_elem2 = result_filtered.findElementFromPath('/proj/src/file.py')
    filtered_diff = file_elem2.attrs.get('_attr_diff', '')
    assert 'hash' in filtered_diff
    assert 'commit_count_30' not in filtered_diff


def test_exclude_attrs_restores_ignoredAttrs():
    """ignoredAttrs must be restored after compareModels, even if exclude_attrs was used."""
    original = ignoredAttrs.copy()

    mc = ModelCompare()
    model1 = SGraph(SElement(None, ''))
    model1.createOrGetElementFromPath('/proj/a.py')
    model2 = SGraph(SElement(None, ''))
    model2.createOrGetElementFromPath('/proj/a.py')

    mc.compareModels(model1, model2, exclude_attrs={'custom_metric_1', 'custom_metric_2'})

    assert ignoredAttrs == original, "ignoredAttrs was not restored after compareModels"


def test_sliding_window_attrs_preset():
    """SLIDING_WINDOW_ATTRS should contain expected metric families."""
    assert 'days_since_modified' in SLIDING_WINDOW_ATTRS
    assert 'commit_count_30' in SLIDING_WINDOW_ATTRS
    assert 'author_list_365' in SLIDING_WINDOW_ATTRS
    assert 'last_modified' in SLIDING_WINDOW_ATTRS
    # Should not contain structural attrs
    assert 'hash' not in SLIDING_WINDOW_ATTRS
    assert 'loc' not in SLIDING_WINDOW_ATTRS
