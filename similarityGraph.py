import numpy as np
import json
import graphviz
import itertools

with open('cmpout/similarity.json', 'r') as json_file:
    data = json.load(json_file)
    adj_matrix = np.array(data["similarity"])
    names = data["names"]
    n = len(names)


def prim_minimum_spanning_tree(adj_matrix):
    num_nodes = len(adj_matrix)
    selected = [False] * num_nodes  # Track visited nodes
    mst_edges = []  # To store the edges in the MST
    total_cost = 0  # Total cost of the MST

    # Start from the first node (index 0)
    selected[0] = True

    for _ in range(num_nodes - 1):
        min_edge = (float('inf'), -1, -1)  # (weight, from_node, to_node)

        # Find the smallest edge that connects a selected node to an unselected node
        for i in range(num_nodes):
            if selected[i]:  # Only consider edges from selected nodes
                for j in range(num_nodes):
                    if not selected[j] and 0 < adj_matrix[i][j] < min_edge[0]:
                        min_edge = (adj_matrix[i][j], i, j)

        # Add the smallest edge to the MST
        weight, from_node, to_node = min_edge
        mst_edges.append((from_node, to_node, weight))
        total_cost += weight
        selected[to_node] = True  # Mark the new node as selected

    return mst_edges, total_cost


def chain_similarity(order):
    s = 0
    for i in range(len(order)-1):
        a = order[i]
        b = order[i+1]
        s += adj_matrix[a, b]
    return s


def best_chain():
    permutations = list(itertools.permutations(range(n)))
    best = np.argmax([chain_similarity(p) for p in permutations])
    return permutations[best]


offset = adj_matrix.max()+1
mst_edges, total_cost = prim_minimum_spanning_tree(
    offset-adj_matrix)


etype = np.zeros_like(adj_matrix)
for e in mst_edges:
    idx = sorted(e[0:2])
    etype[idx[0], idx[1]] |= 1

c = best_chain()
for i in range(n-1):
    idx = sorted(c[i:i+2])
    etype[idx[0], idx[1]] |= 2
    a = c[i]
    b = c[i+1]

np.fill_diagonal(adj_matrix, 0)
for i in range(n):
    j = np.argsort(adj_matrix[i, :])
    idx = sorted([i, j[-1]])
    etype[idx[0], idx[1]] |= 4
    idx = sorted([i, j[-2]])
    etype[idx[0], idx[1]] |= 8


g = graphviz.Graph("G", filename='cmpout/graph')
gc = graphviz.Graph('Gc', filename='cmpout/chain')
gh2 = graphviz.Graph('Gh2', filename='cmpout/highestTwo')
for i in c:
    for j in c:
        label = f"{adj_matrix[i,j]}"
        if etype[i, j] & 4:
            g.edge(names[i], names[j], label=label, style="solid")
            if etype[i, j] & 2:
                gc.edge(names[i], names[j], label=label, style="solid")
            gh2.edge(names[i], names[j], label=label, style="solid")
        else:
            if etype[i, j] & 2:
                gc.edge(names[i], names[j], label=label, style="dashed")

            if etype[i, j] & 1:
                g.edge(names[i], names[j], label=label, style="dashed")

            if etype[i, j] & 8:
                gh2.edge(names[i], names[j], label=label, style="dashed")


g.render()
gc.render()
gh2.render()
