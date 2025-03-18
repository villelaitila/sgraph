from sgraph import SGraph, ModelApi
from sgraph.compare.modelcompare import ModelCompare


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
