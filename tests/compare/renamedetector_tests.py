from sgraph import SGraph, ModelApi
from sgraph.compare.renamedetector import RenameDetector


def test_rename_detection():
    model1 = SGraph.parse_deps_lines('/Servers/Linux/redhat/RHEL6\n'
                                    '/Servers/Windows/WinServer/Win2012 RCE:/Servers/Windows/WinServer/Win2016 RS\n'
                                    '/Servers/Windows/WinServer/Win2012 RCE:/Servers/Linux/redhat/RHEL6\n'
                                    '/Servers/Windows:/Servers/Solaris/SOO\n'
                                    '/Servers/Windows/WinServer/Win1233:/Servers/Solaris\n'.splitlines())
    model_api = ModelApi(model=model1)
    model2 = model_api.filter_model(model1.rootNode, model1)
    rename_element = model2.findElementFromPath('/Servers/Linux/redhat/RHEL6')

    rename_element.rename('RHEL7')

    rename_detector = RenameDetector()
    renames = {}
    rename_detector.identify_rename_pairs(model1.rootNode, model2.rootNode, renames)
    assert model2.findElementFromPath('/Servers/Linux/redhat/RHEL7') is not None
    assert model2.findElementFromPath('/Servers/Linux/redhat/RHEL6') is None
    assert renames[model2.findElementFromPath('/Servers/Linux/redhat/RHEL7')] == 'RHEL6'



def test_rename_detection_2():
    model1 = SGraph.parse_deps_lines('@/Body/Head/Eye:color:blue\n'
                                    '@/Body/Head/Ear:size:medium\n'
                                    '/Body/Head/Brain:/Body/Head/Eye:nerves\n'
                                    '/Body/Head/Eye/Pupil\n'
                                    '/Body/Head/Hair'.splitlines())
    model_api = ModelApi(model=model1)
    model2 = model_api.filter_model(model1.rootNode, model1)
    rename_element = model2.findElementFromPath('/Body/Head/Eye')
    rename_element.rename('Silma')

    model2.findElementFromPath('/Body/Head/Brain').remove()

    rename_detector = RenameDetector()
    renames = {}
    rename_detector.identify_rename_pairs(model1.rootNode, model2.rootNode, renames)
    assert model2.findElementFromPath('/Body/Head/Ear') is not None
    assert model2.findElementFromPath('/Body/Head/Brain') is None
    assert renames[model2.findElementFromPath('/Body/Head/Silma')] == 'Eye'
    print(renames)
