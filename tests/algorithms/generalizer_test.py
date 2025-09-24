from typing import Optional

from sgraph import SGraph
from sgraph.algorithms.generalizer import generalize_model
from sgraph.selement import SElement


def test_basic():
    model = SGraph.parse_deps_lines(['/Servers/Linux/lifoo2',
                                    '/Servers/Windows/wifoo:/Servers/Linux/libar'])
    generalized_model = generalize_model(model, 2)
    assert generalized_model.findElementFromPath('/Servers/Linux/lifoo2') is None
    assert generalized_model.findElementFromPath('/Servers/Linux') is not None
    w: Optional[SElement] = generalized_model.findElementFromPath('/Servers/Windows')
    if w:
        assert w.outgoing[0].toElement.getPath() == '/Servers/Linux'

    model = SGraph.parse_deps_lines('''/Servers1\n
/Servers2:/Servers1:dep
/Servers2:/Servers2:dep'''.splitlines())
    generalized_model = generalize_model(model, 1)
    assert generalized_model.findElementFromPath('/Servers1') is not None
    assert generalized_model.findElementFromPath('/Servers2') is not None

    srv2 = generalized_model.findElementFromPath('/Servers2')
    if srv2:
        assert srv2.outgoing[0].toElement.getPath() == '/Servers1'


def test_basic_2():
    model = SGraph.parse_deps_lines('/Servers/Linux/redhat/RHEL6\n'
                                    '/Servers/Windows/WinServer/Win2012 RCE:/Servers/Windows/WinServer/Win2016 RS\n'
                                    '/Servers/Windows/WinServer/Win2012 RCE:/Servers/Linux/redhat/RHEL6\n'
                                    '/Servers/Windows:/Servers/Solaris/SOO\n'
                                    '/Servers/Windows/WinServer/Win1233:/Servers/Solaris\n'.splitlines())
    # Generalizing the model to the level 2, e.g. /Servers/Linux/redhat/RHEL6 -> /Servers/Linux/redhat
    generalized_model = generalize_model(model, 2)
    assert generalized_model.findElementFromPath('/Servers/Linux/redhat/RHEL6') is None
    assert generalized_model.findElementFromPath('/Servers/Linux') is not None
    w = generalized_model.findElementFromPath('/Servers/Windows')
    if w:
        paths = list(map(lambda ea: ea.toElement.getPath(), w.outgoing))
        assert ['/Servers/Linux', '/Servers/Solaris'] == sorted(paths)


