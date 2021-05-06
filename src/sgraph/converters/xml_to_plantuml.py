import sys

from sgraph.sgraph import SGraph

inputfilepath = sys.argv[1]
outfilepath = None
if len(sys.argv) > 2:
    outfilepath = sys.argv[2]

egm = SGraph.parse_xml(inputfilepath)

if outfilepath:
    print('Node count: {}'.format(egm.rootNode.getNodeCount()))
else:
    pass  # Stdout will be filled with the model data

egm.to_plantuml(outfilepath)
