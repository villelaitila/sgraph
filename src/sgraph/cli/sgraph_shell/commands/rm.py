import os

from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult
from sgraph.cli.sgraph_shell.filesystem.path_handler import create_file_abstraction


class RmCommand:
    def __init__(self):
        pass

    def execute(self, _command_input, cmd, graph, state):
        file = create_file_abstraction(cmd.path_ref, state)
        if not file.exists(graph):
            return CommandResult(output=[], errors=[f'File not exists at'], return_code=1)

        file.resolved_element.remove()
        return CommandResult(output=[], errors=[], return_code=0)

