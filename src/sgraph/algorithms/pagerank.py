
from sgraph import SGraph

def calculate_page_rank(graph: SGraph,
                        d: float = 0.85,
                        max_iterations: int = 100,
                        tolerance: float = 1.0e-6):
    """
    Calculates PageRank scores for the nodes in an sgraph graph.

    The PageRank algorithm computes the importance of nodes in a graph based on
    the structure of incoming links. It simulates a random walker who follows
    links with probability d, or jumps to a random node with probability (1-d).

    Arguments:
        graph (SGraph): graph to be analyzed and enriched with the page_rank attribute
        d (float): damping factor (probability of following links vs random jump)
        max_iterations (int): maximum allowed iterations count
        tolerance (float): convergence tolerance to stop iteration

    Modifies the graph by adding a 'page_rank' attribute to each node.
    The PageRank values sum to 1.0 across all nodes.

    """
    # Step 1: Collect all nodes in the graph using depth-first traversal
    all_elements = []
    stack = [x for x in graph.rootNode.children]
    while stack:
        node = stack.pop()
        all_elements.append(node)
        for child in node.children:
            stack.append(child)
    
    N = len(all_elements)
    
    # Handle empty graph case
    if not graph.rootNode.children:
        return

    # Step 2: Initialize PageRank values - all nodes start with equal probability
    # Use node objects as dictionary keys for efficient lookup
    original_value = 1.0 / N
    pr = {element: original_value for element in all_elements}

    # Step 3: Pre-compute out-degrees for efficiency
    # This avoids recalculating len(node.outgoing) in each iteration
    out_degrees = {node: len(node.outgoing) for node in all_elements}

    # Step 4: Calculate base rank component - the random jump probability
    # This represents the probability of randomly jumping to any node
    base_rank = (1.0 - d) / N

    # Step 5: Main PageRank iteration loop
    for iteration in range(max_iterations):
        new_pr = {}
        total_diff = 0.0

        # Step 5a: Handle "dangling nodes" (nodes without outgoing links)
        # These nodes distribute their PageRank evenly to all nodes in the graph
        dangling_sum = 0.0
        for element, out_degree in out_degrees.items():
            if out_degree == 0:
                dangling_sum += pr[element]

        # Calculate each node's share of the dangling nodes' PageRank
        dangling_share = d * (dangling_sum / N)

        # Step 5b: Calculate new PageRank values for each node
        for node in all_elements:
            link_rank_sum = 0.0

            # Sum PageRank contributions from all incoming links
            for incoming in node.incoming:
                in_node_out_degree = out_degrees.get(incoming.fromElement, 0)

                # Only distribute PageRank if the source node has outgoing links
                if in_node_out_degree > 0:
                    link_rank_sum += pr[incoming.fromElement] / in_node_out_degree

            # Step 5c: Apply the PageRank formula
            # PR(node) = base_rank + dangling_share + d * sum(PR(incoming) / out_degree(incoming))
            new_pr[node] = base_rank + dangling_share + d * link_rank_sum

        # Step 5d: Check for convergence
        total_diff = sum(abs(new_pr[node] - pr[node]) for node in pr)

        # Update PageRank values for next iteration
        pr = new_pr

        if total_diff < tolerance:
            # PageRank values have converged, stop iteration
            break

    # Step 6: Store the final PageRank values as node attributes
    for elem in all_elements:
        elem.attrs['page_rank'] = pr[elem]