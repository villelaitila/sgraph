from sgraph.cli.sgraph_shell.commands.commandresult import CommandResult


# noinspection PyMethodMayBeStatic
class EchoCommand:
    def __init__(self):
        pass

    def execute(self, _command_input, cmd, _graph, _state) -> CommandResult:
        return CommandResult(return_code=0, output=[cmd.something], errors=[])
