import sys


class ExitCommand:
    def __init__(self):
        pass

    def execute(self, _command_input, _cmd, _graph, _state):
        sys.exit(0)
