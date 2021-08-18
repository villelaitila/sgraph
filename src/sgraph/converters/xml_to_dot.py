import sys

from sgraph import SGraph

inputfilepath = sys.argv[1]
outfilepath = None
if len(sys.argv) > 2:
    outfilepath = sys.argv[2]

egm = SGraph.parse_xml_or_zipped_xml(inputfilepath)

def graph_to_dot(g):
    print('digraph G {')
    deps = []

    def handle_elem(elem, indent):
        if elem.children:
            subgraph_id = id(elem)
            c = '	'
            print(c*indent + 'subgraph cluster' + str(subgraph_id) + ' {')

            for child in elem.children:
                if not child.children:
                    n = str(id(child))
                    for assoc in child.outgoing:
                        used = assoc.toElement
                        if used.children:
                            pass
                        else:
                            deps.append((n, str(id(used)), assoc.deptype))

                    print(c*(indent+1) + n + ' [label="' + child.name + '"];')
                else:
                    handle_elem(child, indent+1)
            if elem.name:
                print(c*(indent+1) + 'label = "' + elem.name + '";')
            print(c*indent+'}')
    handle_elem(g.rootNode, indent=1)
    print('')
    for a, b, t in deps:
        print('   ' + a + ' -> ' + b + ' [label = "' + t + '"];')
    print('}')



graph_to_dot(egm)