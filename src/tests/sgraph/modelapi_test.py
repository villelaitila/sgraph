from src.sgraph.modelapi import ModelApi
from src.sgraph.loader import ModelLoader
import os

MODEL_PATH = '/nginx/src/core/'

# Helper for creating the model and model api
def get_model_and_model_api(file_name):
    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, file_name)    
    modelLoader = ModelLoader()
    model = modelLoader.load_model(filename)
    return model, ModelApi(model=model)


def test_filter_model():
    model, model_api = get_model_and_model_api('modelfile.xml')

    # Check that model root node has two children nginx and foo
    assert 2 == len(model.rootNode.children)
    assert "nginx" == model.rootNode.children[0].name
    assert "foo" == model.rootNode.children[1].name

    elem1 = model.createOrGetElementFromPath('/nginx')
    subgraph1 = model_api.filter_model(elem1, model)

    # Subgraph should now have nginx but not foo
    assert 1 == len(subgraph1.rootNode.children)
    assert "nginx" == subgraph1.rootNode.children[0].name


def test_filter_model_keeps_children_of_outgoing_dependency():
    model, model_api = get_model_and_model_api('modelfile.xml')
    nginxc_element = model.createOrGetElementFromPath(f'{MODEL_PATH}nginx.c')
    subgraph = model_api.filter_model(nginxc_element, model)
    nginxh_element = subgraph.createOrGetElementFromPath(f'{MODEL_PATH}nginx.h')
    assert 1 == len(nginxh_element.children)
    assert 'testname' == nginxh_element.children[0].name
    assert 'testtype' == nginxh_element.children[0].attrs['type']
