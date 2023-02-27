from sgraph.cli.sgraph_shell.filesystem.fileabstraction import FileAbstraction


def resolve_path_expression(path, current_path):
    if path.startswith('/'):
        return path

    current = current_path
    while path.startswith('../'):
        if '/' in current:
            current = current[:current.rfind('/')]
            path = path[path.find('/') + 1:]

    if current != '/':
        combined = current + '/' + path if path != '.' else current
    else:
        combined = '/' + path if path != '.' else '/'

    while '/..' in combined:
        pos = combined.find('/..')
        prev_pos = combined[:pos].rfind('/') + 1
        beginning = combined[0:prev_pos]
        rest = combined[pos + 3:]
        combined = beginning + rest

    return combined


def create_file_abstraction(relative_path, state) -> FileAbstraction:
    absolute_path = resolve_path_expression(relative_path, state['current_location'].getPath())
    return create_file_abstraction_abs(absolute_path, relative_path)


def create_file_abstraction_abs(absolute_path, relative_path) -> FileAbstraction:
    from sgraph.cli.sgraph_shell.filesystem.associationsfile import AssociationsFile
    from sgraph.cli.sgraph_shell.filesystem.attributesfile import AttributesFile
    from sgraph.cli.sgraph_shell.filesystem.elementfile import ElementFile

    if absolute_path.endswith('/attributes.json'):
        return AttributesFile(absolute_path, relative_path)
    elif absolute_path.endswith('/outgoing.json'):
        return AssociationsFile(absolute_path, relative_path, mode='outgoing')
    elif absolute_path.endswith('/incoming.json'):
        return AssociationsFile(absolute_path, relative_path, mode='incoming')
    else:
        return ElementFile(absolute_path, relative_path)
