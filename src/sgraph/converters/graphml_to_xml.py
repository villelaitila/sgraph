import sys

from sgraph.converters.graphml import graphml_to_sgraph

with open(sys.argv[1]) as f:
    s = f.read()
    g = graphml_to_sgraph(s)
    names = []
    for e in g.rootNode.children:
        for n in e.children:
            print(n.getPath())
            names.append(n.name)

    names.sort()
    for n in names:
        print(n)
    g.to_xml(fname=sys.argv[2])