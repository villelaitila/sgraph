import os
import sys

from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult
from sgraph.cli.sgraph_shell.filesystem.path_handler import create_file_abstraction


# noinspection PyMethodMayBeStatic
class MkdirCommand:
    def __init__(self):
        pass

    def execute(self, _command_input, cmd, graph, state) -> CommandResult:
        file = create_file_abstraction(cmd.path_ref, state)
        # TODO Support mkdir -p
        if file.exists(graph):
            return CommandResult(output=[], errors=[f'File exists at'], return_code=1)

        parent_dir_path = os.path.dirname(cmd.path_ref)
        if parent_dir_path == '':
            parent_dir_path = '/'
        parent_dir = create_file_abstraction(parent_dir_path, state)
        if not parent_dir.exists(graph):
            return CommandResult(output=[], errors=[f'Parent directory does not exist.'],
                                 return_code=1)

        parent_dir.resolved_element.createOrGetElement(os.path.basename(cmd.path_ref))
        return CommandResult(output=[], errors=[], return_code=0)

