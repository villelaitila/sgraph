from __future__ import annotations

from sgraph import SElement, SGraph
from sgraph.attributes import attributequeries


class MetricsApi:
    def __init__(self):
        pass

    def get_total_loc_metrics(self, modeldir: str) -> dict[str, int | float]:
        """
        Get total LOC metrics describing one model,
        such as "loc" (lines of code) and "avg_file_loc" (average code file size).
        Currently returns only loc and avg_file_loc. In future this function might be
        relevant for checking total amount (in LOC) of test code.

        :param modeldir: model output dir (timestamp dir)

        :return: Returns data like {'loc': 1203, 'avg_file_loc': 123.3040840}
        """
        columns, entries = attributequeries.read_attrs_generic(  # type: ignore
            modeldir + '/content/loc/attr_loc_propagated.csv')
        total_loc = 0
        for filepath, attrs in entries:
            if 'loc' in columns:
                splitted = filepath.split('/')
                if len(splitted) == 2:
                    # / Root
                    total_loc = int(attrs['loc'])

        _notused, entries = attributequeries.read_attrs_generic(modeldir +
                                                                '/content/loc/_attr_loc.csv')
        avg_loc = 0.0
        if len(entries) > 0:
            avg_loc = total_loc / len(entries)

        return {'loc': total_loc, 'avg_file_loc': avg_loc}

    def get_total_tech_debt_metrics(self, modeldir: str) -> dict[str, int | float]:
        """
        Get tech debt metrics describing one model,
        such as "tech_debt_markers_count" (how many FIXMEs etc in code).

        :param modeldir: model output dir (timestamp dir)
        not supported yet.

        :return: Returns data like {'tech_debt_markers_count': 1203}
        """
        total_loc = self.get_total_loc_metrics(modeldir)['loc']

        columns, entries = attributequeries.read_attrs_generic(modeldir +
                                                               '/attr_tech_debt_propagated.csv')
        c = 0
        for filepath, attrs in entries:
            if 'tech_debt_markers_count' in columns:
                splitted = filepath.split('/')
                if len(splitted) == 2:
                    # / Root
                    c = int(attrs['tech_debt_markers_count'])

        d = 0.0
        if total_loc > 0:
            d = round(c / (total_loc / 1000), 1)

        return {'tech_debt_markers_count': c, 'tech_debt_density': d}

    def get_tech_debt_metrics(self, model: SGraph) -> dict[str, dict[str, list[int | float]]]:
        """
        Get tech debt metrics describing one model,
        such as "tech_debt_markers_count" (how many FIXMEs etc in code).

        :param model: graph model
        :return: Returns data like {'tech_debt_markers_count': 1203}
        """
        def populate_tech_debt_markers_count(x: SElement):
            if 'tech_debt_markers_count' in x.attrs:
                if len(x.children) > 0:
                    bd = {}
                    for c in x.children:
                        bd[c.name] = populate_tech_debt_markers_count(c)
                    return [int(x.attrs['tech_debt_markers_count']), bd]
                else:
                    return [int(x.attrs['tech_debt_markers_count'])]
            else:
                return [0]

        markers = {}

        for c in model.rootNode.children:
            markers[c.name] = populate_tech_debt_markers_count(c)

        def populate_tech_debt_density(x):
            if 'tech_debt_markers_count' in x.attrs:
                loc = get_loc_or_testcode_loc(x)
                if loc > 0:
                    d = round(int(x['tech_debt_markers_count']) / (loc / 1000), 1)
                else:
                    d = 0

                if len(x.children) > 0:
                    bd = {}
                    for c in x.children:
                        bd[c.name] = populate_tech_debt_density(c)
                    return [d, bd]
                return [d]
            else:
                return [0]

        density = {}

        for c in model.rootNode.children:
            density[c.name] = populate_tech_debt_density(c)

        return {'tech_debt_markers_count': markers, 'tech_debt_density': density}

    def get_metrics_by_name(self, name, model: SGraph, with_breakdown):
        """
        Get metric values by kpi name
        such as "architecture_modularity" and "risk_density"

        Does not yet support with_breakdown=True

        :param name: attribute name
        :param model: SGraph model
        :param with_breakdown: with breakdown means directory sub totals included,
        not supported yet.

        :return: Returns data like {'tech_debt_markers_count': 1203}
        """
        if not with_breakdown:
            value = 0
            found = False
            for e in model.rootNode.children:
                if name in e.attrs:
                    if isinstance(e.attrs[name], str):
                        try:
                            attr_value = e.attrs[name]
                            if isinstance(attr_value, list):
                                raise Exception('Invalid attribute type')
                            value = float(attr_value)
                            found = True
                        except ValueError:
                            try:
                                attr_value = e.attrs[name]
                                if isinstance(attr_value, list):
                                    raise Exception('Invalid attribute type')
                                value = int(attr_value)
                                found = True
                            except ValueError:
                                pass
                    else:
                        value = e.attrs[name]
                        found = True
            if not found:
                return None
            return {name: value}
        else:
            raise Exception('Not implemented')


def get_loc_or_testcode_loc(e: SElement):
    loc: int = 0
    if 'loc' in e.attrs:
        attr_value = e.attrs['loc']
        if isinstance(attr_value, list):
            raise Exception('Invalid attribute type')
        loc += int(attr_value)
    if 'testcode_loc' in e.attrs:
        attr_value = e.attrs['testcode_loc']
        if isinstance(attr_value, list):
            raise Exception('Invalid attribute type')
        loc += int(attr_value)
    return loc
