from sgraph import ModelApi
from sgraph.loader import ModelLoader
import os

from sgraph.modelapi import FilterAssocations, HaveAttributes

MODEL_PATH = '/nginx/src/core/'
MODELFILE = 'modelfile.xml'

# Helper for creating the model and model api
def get_model_and_model_api(file_name):
    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, file_name)
    modelLoader = ModelLoader()
    model = modelLoader.load_model(filename)
    return model, ModelApi(model=model)


def test_filter_model():
    model, model_api = get_model_and_model_api(MODELFILE)

    # Check that model root node has two children nginx and foo
    assert 5 == len(model.rootNode.children)
    assert None is not model.rootNode.getChildByName('nginx')
    assert None is not model.rootNode.getChildByName('foo')

    elem1 = model.createOrGetElementFromPath('/nginx')
    subgraph1 = model_api.filter_model(elem1, model)

    assert ['directory-that-depends-on-nginx.c', 'nginx',
            'used-directly-from-nginx'] == sorted([x.name for x in subgraph1.rootNode.children])

    elem = subgraph1.findElementFromPath(
        '/used-directly-from-nginx/src/used-directly-from-nginx.c/child/child-of-child/child-of-child-of-child'  # noqa
    )
    assert None is not elem
    assert 'testvalue1' == elem.attrs['test_attribute1']


def test_filter_model_keeps_children_of_outgoing_dependency():
    model, model_api = get_model_and_model_api(MODELFILE)
    nginxc_element = model.createOrGetElementFromPath(f'{MODEL_PATH}nginx.c')
    subgraph = model_api.filter_model(nginxc_element, model)
    nginxh_element = subgraph.createOrGetElementFromPath(f'{MODEL_PATH}nginx.h')
    assert 1 == len(nginxh_element.children)
    assert 'testname' == nginxh_element.children[0].name
    assert 'testtype' == nginxh_element.children[0].attrs['type']


def test_filter_model_with_ignore_param():
    model, model_api = get_model_and_model_api(MODELFILE)
    elem1 = model.createOrGetElementFromPath('/nginx')
    subgraph1 = model_api.filter_model(elem1, model, filter_outgoing=FilterAssocations.Ignore,
                                       filter_incoming=FilterAssocations.Ignore)
    assert ['nginx'] == sorted([x.name for x in subgraph1.rootNode.children])


def test_filter_model_direct():
    model, model_api = get_model_and_model_api(MODELFILE)
    nginxc_element = model.createOrGetElementFromPath(f'{MODEL_PATH}nginx.c')
    subgraph = model_api.filter_model(nginxc_element, model,
                                      filter_incoming=FilterAssocations.Direct,
                                      filter_outgoing=FilterAssocations.Direct)
    nginxh_element = subgraph.createOrGetElementFromPath(f'{MODEL_PATH}nginx.h')
    assert 1 == len(nginxh_element.children)
    assert 'testname' == nginxh_element.children[0].name
    assert 'testtype' == nginxh_element.children[0].attrs['type']


def test_filter_model_with_indirect():
    model, model_api = get_model_and_model_api(MODELFILE)
    elem1 = model.createOrGetElementFromPath('/nginx')
    subgraph1 = model_api.filter_model(elem1, model,
                                       filter_outgoing=FilterAssocations.DirectAndIndirect,
                                       filter_incoming=FilterAssocations.DirectAndIndirect)
    assert [
               'directory-that-depends-on-nginx.c', 'nginx', 'used-directly-from-nginx',
               'used-indirectly-from-nginx'
           ] == sorted([x.name for x in subgraph1.rootNode.children])

    elem = subgraph1.findElementFromPath('/used-indirectly-from-nginx/src/cyclical-problem.c')
    assert None is not elem
    assert 'simple dependency cycle' == elem.attrs['description']

    elem = subgraph1.findElementFromPath(
        '/used-indirectly-from-nginx/src/used-indirectly-from-nginx.c/child/child-of-child/child-of-child-of-child'
        # noqa
    )
    assert None is not elem
    assert 'testvalue2' == elem.attrs['test_attribute2']


def test_filter_model_with_indirect_incoming():
    model, model_api = get_model_and_model_api(MODELFILE)
    used_indirectly_element = model.createOrGetElementFromPath(
        '/used-indirectly-from-nginx/src/used-indirectly-from-nginx.c')
    subgraph = model_api.filter_model(
        used_indirectly_element, model,
        filter_outgoing=FilterAssocations.Ignore,
        filter_incoming=FilterAssocations.DirectAndIndirect)
    # Subgraph root should have all children but foo
    # (no dependencies reach foo)
    assert len(subgraph.rootNode.children) == 4, \
        'subgraph root node did not have correct amount of children'


def test_filter_model_with_indirect_outcoming_incoming():
    model, model_api = get_model_and_model_api('modelfile_direct_indirect.xml')
    used_indirectly_element = model.createOrGetElementFromPath(
        '/foo/bar')
    subgraph = model_api.filter_model(
        used_indirectly_element, model,
        filter_outgoing=FilterAssocations.DirectAndIndirect,
        filter_incoming=FilterAssocations.DirectAndIndirect)

    # Subgraph should have other-1 as the only child of other (not other-2)
    other = subgraph.rootNode.children[1]
    assert other.name == 'other'
    assert len(other.children) == 1
    assert other.children[0].name == 'other-1'


def test_filter_model_with_attributes():
    model, model_api = get_model_and_model_api(MODELFILE)
    used_indirectly_element = model.createOrGetElementFromPath(
        '/used-indirectly-from-nginx/src/used-indirectly-from-nginx.c')
    subgraph_no_attrs = model_api.filter_model(
        used_indirectly_element, model,
        filter_outgoing=FilterAssocations.Ignore,
        filter_incoming=FilterAssocations.DirectAndIndirect,
        have_attributes=HaveAttributes.Ignore)

    stack = [subgraph_no_attrs.rootNode]
    while stack:
        elem = stack.pop()
        for child in elem.children:
            print(child.getPath())
            assert not child.attrs
            stack.append(child)

def test_filter_model_with_attributes_copy():
    original_model, model_api = get_model_and_model_api(MODELFILE)
    used_indirectly_element = original_model.createOrGetElementFromPath(
        '/used-indirectly-from-nginx/src/used-indirectly-from-nginx.c')

    subgraph_attrs_copy = model_api.filter_model(
        used_indirectly_element, original_model,
        filter_outgoing=FilterAssocations.Ignore,
        filter_incoming=FilterAssocations.DirectAndIndirect,
        have_attributes=HaveAttributes.IncludeCopy)

    attributes = set()
    stack = [subgraph_attrs_copy.rootNode]
    while stack:
        elem = stack.pop()
        for child in elem.children:
            if child.attrs:
                attributes.update(child.attrs.keys())
            stack.append(child)
    print(attributes)
    assert len(attributes) == 5

    original_model.createOrGetElementFromPath('/asdf/aqwer').attrs['test_attribute1'] = 'testvalue1'

    assert 'test_attribute1' not in subgraph_attrs_copy.createOrGetElementFromPath('/asdf/aqwer').attrs.keys()
    print(subgraph_attrs_copy.to_deps(None))


def test_filter_model_with_attributes_ref():
    original_model, model_api = get_model_and_model_api(MODELFILE)
    e = '/used-indirectly-from-nginx/src/used-indirectly-from-nginx.c'
    used_indirectly_element = original_model.createOrGetElementFromPath(e)

    m2 = model_api.filter_model(
        used_indirectly_element, original_model,
        filter_outgoing=FilterAssocations.Ignore,
        filter_incoming=FilterAssocations.DirectAndIndirect,
        have_attributes=HaveAttributes.IncludeReference)

    original_model.createOrGetElementFromPath(e).attrs['test_attribute1'] = 'testvalue1'
    attributes = set()
    stack = [m2.rootNode]
    while stack:
        elem = stack.pop()
        for child in elem.children:
            if child.attrs:
                attributes.update(child.attrs.keys())
            stack.append(child)
    assert len(attributes) == 5
    assert (original_model.createOrGetElementFromPath(e).attrs == m2.createOrGetElementFromPath(e).attrs)
    print(m2.to_deps(None))

