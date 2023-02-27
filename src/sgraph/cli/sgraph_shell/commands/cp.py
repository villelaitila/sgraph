import os
import sys

from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult
from sgraph.cli.sgraph_shell.filesystem.path_handler import create_file_abstraction


class CpCommand:
    def __init__(self):
        pass

    def execute(self, _command_input, cmd, graph, state) -> CommandResult:
        from_file = create_file_abstraction(cmd.from_path, state)
        if not from_file.exists(graph):
            return CommandResult(output=[],
                                 errors=[f'Source does not exist {from_file.absolute_path}'],
                                 return_code=1)

        file = create_file_abstraction(cmd.to_path, state)
        if file.isfile(graph):
            return CommandResult(output=[], errors=[f'File exists at'], return_code=1)
        elif file.isdir(graph):
            parent_dir = file
        else:
            parent_dir_path = os.path.dirname(cmd.path_ref)
            parent_dir = create_file_abstraction(parent_dir_path, state)

        if not parent_dir.exists(graph):
            return CommandResult(output=[], errors=[f'Parent directory {file.absolute_path} of target'
                                                    f'does not exist.'],
                                 return_code=1)

        e = from_file.resolved_element

        e.parent = parent_dir.resolved_element

        new_elem = parent_dir.resolved_element.createOrGetElement(e.name)
        new_elem.attrs = dict(e.attrs)

        return CommandResult(output=[], errors=[], return_code=0)
