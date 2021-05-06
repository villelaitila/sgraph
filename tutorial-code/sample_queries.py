import sys
from sgraph.loader.model_loader import ModelLoader
from sgraph.modelapi import ModelApi


def main(model_path):
    ml = ModelLoader()
    model = ml.load_model(model_path)
    api = ModelApi(model=model)

    # Basic model handling
    project = api.model.rootNode.children[0]
    print("Project {}".format(project.name))

    repos = [e for e in project.children]
    print("Repos {}".format(', '.join([e.name for e in repos])))

    for r in repos:
        print("- Total LOC in repo {}: {}".format(r.name, r.attrs.get('loc', '(not available)')))

    # Graph traversal
    print()
    for r in repos:
        print("Node {}:".format(r.getPath()))
        print(" - parent: {}".format(r.parent.name))
        print(" - kids: \n   - {}".format('\n   - '.join([e.name for e in r.children])))
        print(" - attributes: \n   - {}".format('\n   - '.join(r.attrs.keys())))

        loc = r.attrs.get('loc')
        if loc:
            print(" - total lines of code: {}".format(loc))

    # Finding element by name
    search = "test"
    nodes = api.getElementsByName(search)
    print()
    print('Following nodes are named "{}"'.format(search))
    for n in nodes:
        print("- {}".format(n.getPath()))


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        print("Usage: python3 sample_queries.py <path to modelfile.xml.zip>")
