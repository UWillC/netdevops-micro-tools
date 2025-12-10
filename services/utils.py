def compare_versions(v1: str, v2: str) -> int:
    """
    Compare versions lexicographically.
    Return:
      -1 if v1 < v2
       0 if v1 == v2
       1 if v1 > v2
    """
    def norm(v):
        parts = []
        for p in v.split("."):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return parts

    a = norm(v1)
    b = norm(v2)

    for i in range(max(len(a), len(b))):
        ai = a[i] if i < len(a) else 0
        bi = b[i] if i < len(b) else 0
        if ai < bi:
            return -1
        if ai > bi:
            return 1
    return 0
