import json
import os

from sgraph.cli.sgraph_shell.filesystem.fileabstraction import FileAbstraction


class AttributesFile(FileAbstraction):

    def __init__(self, absolute_path, relative_path):
        super().__init__(absolute_path, relative_path)
        pass

    def content(self):
        return json.dumps(self.resolved_element.attrs, indent=4)

    def isfile(self, graph):
        self.resolve_element(graph)
        if self.resolved_element:
            return self.resolved_element.attrs
        return False

    def exists(self, graph):
        return self.isfile(graph)

    def resolve_element(self, graph):
        if not self.resolved:
            self.resolved_element = graph.findElementFromPath(os.path.dirname(self.absolute_path))
            self.resolved = True
