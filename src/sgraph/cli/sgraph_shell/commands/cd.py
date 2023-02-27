from sgraph.cli.sgraph_shell.commands.commandabstraction import CommandAbstraction
from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult
from sgraph.cli.sgraph_shell.filesystem.path_handler import create_file_abstraction


class CdCommand(CommandAbstraction):

    def __init__(self):
        pass

    def execute(self, command_input, cmd, graph, state) -> CommandResult:
        # originally this simple: path_split = [x.pathName for x in cmd.pathParts]

        file = create_file_abstraction(cmd.path_ref, state)
        is_file = file.isfile(graph)
        if not is_file:
            if file.exists(graph):
                # Change it!
                state['current_location'] = file.resolved_element
            else:
                return CommandResult(output=[], errors=[f'Path not found: {cmd.path_ref}'],
                                     return_code=1)
        else:
            return CommandResult(output=[], errors=[f'Not a directory: {cmd.path_ref}'],
                                 return_code=1)

        return CommandResult(output=[], errors=[], return_code=0)
