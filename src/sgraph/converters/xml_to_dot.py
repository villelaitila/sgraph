import sys

from sgraph import SGraph, SElement

if len(sys.argv) < 2:
    # Read the XML or XML.zip from stdin
    egm = SGraph.parse_xml_or_zipped_xml(sys.stdin)
else:
    inputfilepath = sys.argv[1]
    egm = SGraph.parse_xml_or_zipped_xml(inputfilepath)

outfilepath = None
if len(sys.argv) > 2:
    outfilepath = sys.argv[2]


def graph_to_dot(g: SGraph):
    print('digraph G {')
    # Global styling for a more professional look
    print('   graph [fontname="Inter, Helvetica, Arial", fontsize=10, labelloc="t", bgcolor="#ffffff", pad=0.3, nodesep=0.35, ranksep=0.5, splines=true];')
    print('   node  [fontname="Inter, Helvetica, Arial", fontsize=9, shape=box, style="filled,rounded", color="#D0D7DE", fillcolor="#F6F8FA", penwidth=1.0];')
    print('   edge  [fontname="Inter, Helvetica, Arial", fontsize=8, color="#6E7781", penwidth=1.1, arrowsize=0.7];')
    deps: list[tuple[str, str, str]] = []

    def handle_elem(elem: SElement, indent: int):
        if elem.children:
            subgraph_id = id(elem)
            c = '	'
            print(c*indent + 'subgraph cluster' + str(subgraph_id) + ' {')
            # Cluster styling
            print(c*(indent+1) + 'style="rounded,filled";')
            print(c*(indent+1) + 'color="#BBD0FF";')
            print(c*(indent+1) + 'fillcolor="#EFF4FF";')

            for child in elem.children:
                if not child.children:
                    n = str(id(child))
                    for assoc in child.outgoing:
                        used = assoc.toElement
                        if used.children:
                            pass
                        else:
                            deps.append((n, str(id(used)), assoc.deptype))

                    # Leaf node styling inherits global, but allow per-node tweaks later
                    print(c*(indent+1) + n + ' [label="' + child.name.replace('"','\"') + '"];')
                else:
                    handle_elem(child, indent+1)
            if elem.name:
                print(c*(indent+1) + 'label = "' + elem.name.replace('"','\"') + '";')
            print(c*indent+'}')
    handle_elem(g.rootNode, indent=1)
    print('')
    # Edge styling by dependency type
    print('   // Edge style legend by dependency type')
    dep_styles = {
        'uses': {'color': '#1F6FEB', 'penwidth': '1.4'},
        'extends': {'color': '#9A6700', 'style': 'dashed', 'penwidth': '1.2'},
        'implements': {'color': '#116329', 'style': 'dotted', 'penwidth': '1.2'},
        'imports': {'color': '#8250DF', 'penwidth': '1.2'},
        'calls': {'color': '#F85149', 'penwidth': '1.3'},
    }
    for a, b, t in deps:
        style = dep_styles.get(t, {'color': '#6E7781'})
        attrs = [f'color = "{style["color"]}"']
        if 'style' in style:
            attrs.append(f'style = "{style["style"]}"')
        if 'penwidth' in style:
            attrs.append(f'penwidth = {style["penwidth"]}')
        label_attr = f'label = "{t}"' if t else ''
        attr_str = ', '.join([label_attr] + attrs) if label_attr else ', '.join(attrs)
        print('   ' + a + ' -> ' + b + ' [' + attr_str + '];')
    print('}')



graph_to_dot(egm)