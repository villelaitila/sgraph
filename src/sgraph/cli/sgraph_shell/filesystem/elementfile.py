from sgraph.cli.sgraph_shell.filesystem.fileabstraction import FileAbstraction


class ElementFile(FileAbstraction):

    def __init__(self, absolute_path, relative_path):
        super().__init__(absolute_path, relative_path)
        pass

    def isfile(self, _graph):
        return False

    def exists(self, graph):
        self.resolve_element(graph)
        return self.resolved_element