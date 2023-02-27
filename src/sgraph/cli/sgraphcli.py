import argparse



def handle_help_command(args):
    print(args.help)


def handle_shell_command(args):
    from sgraph import SGraph
    graph = SGraph.parse_xml_or_zipped_xml(args.arg2)
    from sgraph.cli.sgraph_shell.shell import enter_shell
    enter_shell(graph)


def cli_main():
    parser = argparse.ArgumentParser(prog='sgraph', description='What the program does',
                                     epilog='Text at the bottom of help')
    parser.add_argument('command')
    parser.add_argument('arg2')
    args = parser.parse_args()
    if args.command == 'help':
        handle_help_command(args)
    elif args.command == 'shell':
        handle_shell_command(args)
