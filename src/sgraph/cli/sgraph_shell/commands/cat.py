from sgraph.cli.sgraph_shell.commands.commandabstraction import CommandAbstraction
from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult
from sgraph.cli.sgraph_shell.filesystem.path_handler import create_file_abstraction


class CatCommand(CommandAbstraction):

    def __init__(self):
        pass

    def execute(self, command_input, cmd, graph, state) -> CommandResult:
        try:
            file = create_file_abstraction(cmd.path_ref, state)
            if file.isfile(graph):
                return CommandResult(output=[file.content()], errors=[''], return_code=0)
            else:
                return CommandResult(output=[], errors=[f'Path not exists {cmd.path_ref}'],
                                     return_code=1)
        except Exception as e:
            return CommandResult(output=[], errors=[f'Error with path: {cmd.path_ref}',
                                                    f'err={e}'], return_code=1)
