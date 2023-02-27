
class FileAbstraction:

    def __init__(self, absolute_path, relative_path):
        self.relative_path = relative_path
        self.absolute_path = absolute_path
        self.resolved_element = None
        self.resolved = False

    def content(self):
        raise Exception('Not implemented')

    def isfile(self, _graph):
        raise Exception('Not implemented')

    def exists(self, _graph):
        raise Exception('Not implemented')

    def isdir(self, graph):
        return self.exists(graph) and not self.isfile(graph)

    def resolve_element(self, graph):
        if not self.resolved:
            self.resolved_element = graph.findElementFromPath(self.absolute_path)
            self.resolved = True
