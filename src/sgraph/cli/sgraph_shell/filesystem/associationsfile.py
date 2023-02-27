from sgraph.cli.sgraph_shell.filesystem.fileabstraction import FileAbstraction


class AssociationsFile(FileAbstraction):

    def __init__(self, absolute_path, relative_path, mode):
        super().__init__(absolute_path, relative_path)
        self.mode = mode

    def isfile(self, graph):
        self.resolve_element(graph)
        if self.resolved_element:
            if self.mode == 'incoming':
                return self.resolved_element.incoming
            else:
                return self.resolved_element.outgoing
        return False

    def exists(self, graph):
        return self.isfile(graph)

    def resolve_element(self, graph):
        if not self.resolved:
            self.resolved_element = graph.findElementFromPath(os.path.dirname(self.absolute_path))
            self.resolved = True
