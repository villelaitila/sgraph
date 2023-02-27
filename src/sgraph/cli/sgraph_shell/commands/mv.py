import os
import sys
from typing import Any, List, Dict

from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult
from sgraph.cli.sgraph_shell.filesystem.path_handler import create_file_abstraction


class MvCommand:
    def __init__(self):
        pass

    def execute(self, _command_input: List[str], cmd, graph, state: Dict[str, Any]) -> CommandResult:
        from_file = create_file_abstraction(cmd.from_path, state)
        if not from_file.exists(graph):
            return CommandResult(output=[],
                                 errors=[f'Source does not exist {from_file.absolute_path}'],
                                 return_code=1)

        file = create_file_abstraction(cmd.to_path, state)
        # TODO Support mkdir -p
        element_name = from_file.resolved_element.name
        if file.isfile(graph):
            return CommandResult(output=[], errors=[f'File exists at'], return_code=1)
        elif file.isdir(graph):
            parent_dir = file
        else:
            parent_dir_path = os.path.dirname(file.absolute_path)
            element_name = os.path.basename(file.absolute_path)
            parent_dir = create_file_abstraction(parent_dir_path, state)

        if not parent_dir.exists(graph):
            return CommandResult(output=[], errors=[f'Parent directory {file.absolute_path} of '
                                                    f'target does not exist.'],
                                 return_code=1)

        if element_name in parent_dir.resolved_element.childrenDict:
            return CommandResult(output=[], errors=[f'Parent directory {file.absolute_path} '
                                                    f'contains already a file or a directory with'
                                                    f' name {element_name}'], return_code=1)

        e = from_file.resolved_element
        old_parent = e.parent
        new_parent = parent_dir.resolved_element
        if old_parent == new_parent:
            # rename only
            if e.name == element_name:
                return CommandResult(output=[], errors=['Move to itself not allowed'], return_code=1)
            e.name = element_name
        else:
            old_parent.children.remove(e)
            old_parent.childrenDict.pop(e.name)

            e.parent = new_parent

            if e.name != element_name:
                e.name = element_name  # Rename also.

            new_parent.children.append(e)
            new_parent.childrenDict[e.name] = e

        return CommandResult(output=[], errors=[], return_code=0)
