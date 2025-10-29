def set_if(d: dict, path: list, value):
    x = d
    for k in path[:-1]:
        x = x.setdefault(k, {})
    x[path[-1]] = value
