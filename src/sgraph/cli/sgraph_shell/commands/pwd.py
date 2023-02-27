from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult
from sgraph.cli.sgraph_shell.filesystem.path_handler import create_file_abstraction


class PwdCommand:
    def __init__(self):
        pass

    def execute(self, _command_input, _cmd, _graph, state) -> CommandResult:
        return CommandResult(output=[state['current_location'].getPath()], errors=[''],
                             return_code=0)
