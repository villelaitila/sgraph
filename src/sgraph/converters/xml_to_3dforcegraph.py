import json
import sys

from sgraph import SGraph

inputfilepath = sys.argv[1]
outfilepath = None
if len(sys.argv) > 2:
    outfilepath = sys.argv[2]

egm = SGraph.parse_xml_or_zipped_xml(inputfilepath)

if outfilepath:
    print('Node count: {}'.format(egm.rootNode.getNodeCount()))
else:
    pass  # Stdout will be filled with the model data

elem_to_id_map = {}


class Counter:
    def __init__(self):
        self.i = 1

    def now(self):
        self.i += 1
        return self.i


counter = Counter()

child_parent_links = []

nodes = []
links = []


def traverse_parent_child(elem, parent_id):
    this_id = counter.now()
    elem_to_id_map[elem] = this_id
    nodes.append({'id': this_id, 'name': elem.name, 'val': 5})
    if parent_id != -1:
        links.append({"source": this_id, "target": parent_id})

    for c in elem.children:
        traverse_parent_child(c, this_id)


traverse_parent_child(egm.rootNode, -1)


def traverse_assocs(elem):

    for association in elem.outgoing:
        links.append({"source": elem_to_id_map[elem], "target":
            elem_to_id_map[association.toElement]})

    for c in elem.children:
        traverse_assocs(c)


traverse_assocs(egm.rootNode)

output_data = {'nodes': nodes, 'links': links}

# TODO For larger data, use dump to file instead
json_text = json.dumps(output_data)

if outfilepath:
    with open(outfilepath, 'w') as f:
        f.write(f'const gData = {json_text};\n')
else:
    print(f'const gData = {json_text};')
