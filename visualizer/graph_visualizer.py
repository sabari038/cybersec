def get_graph_data(graph):
    nodes = [{"id": n, "label": str(n)} for n in graph.nodes()]
    edges = [{"from": u, "to": v} for u, v in graph.edges()]
    return {"nodes": nodes, "edges": edges}
