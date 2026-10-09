"""IP range membership, and a list whose content changes over time."""
import bisect
import ipaddress


class RangeSet:
    """Sorted, merged integer ranges. Membership is one binary search per address family."""

    def __init__(self, prefixes):
        spans = {4: [], 6: []}
        for p in prefixes:
            net = ipaddress.ip_network(p, strict=False)
            spans[net.version].append((int(net.network_address), int(net.broadcast_address)))
        self.starts, self.ends = {}, {}
        for v, items in spans.items():
            items.sort()
            merged = []
            for s, e in items:
                if merged and s <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], e))
                else:
                    merged.append((s, e))
            self.starts[v] = [s for s, _ in merged]
            self.ends[v] = [e for _, e in merged]

    def __contains__(self, addr):
        v, n = addr.version, int(addr)
        i = bisect.bisect_right(self.starts[v], n) - 1
        return i >= 0 and n <= self.ends[v][i]


class VersionedList:
    """One vendor list over time.

    versions: [(first_day, last_day, cid)] sorted by first_day, days as date ordinals. A version is in force
    from its first_day until the next version's first_day. contents: {cid: [prefix, ...]}.
    """

    CACHE_MAX = 200_000

    def __init__(self, versions, contents):
        self.versions = sorted(versions)
        self.firsts = [f for f, _, _ in self.versions]
        self.sets = {cid: RangeSet(p) for cid, p in contents.items()}
        self.contents = contents
        self._holding = {}

    def holding(self, addr):
        """Content ids of every version that holds addr."""
        key = int(addr), addr.version
        found = self._holding.get(key)
        if found is None:
            if len(self._holding) > self.CACHE_MAX:
                self._holding.clear()
            found = self._holding[key] = frozenset(cid for cid, s in self.sets.items() if addr in s)
        return found

    def in_force(self, day):
        """Index of the version in force on day. Before the first version, the first one is used."""
        return max(bisect.bisect_right(self.firsts, day) - 1, 0)

    def distance(self, addr, day):
        """Days from day to the nearest version that holds addr, or None if no version ever held it."""
        held = self.holding(addr)
        if not held:
            return None
        best = None
        for i, (first, last, cid) in enumerate(self.versions):
            if cid not in held:
                continue
            end = self.firsts[i + 1] - 1 if i + 1 < len(self.versions) else max(last, day)
            d = 0 if first <= day <= end else min(abs(day - first), abs(day - end))
            best = d if best is None else min(best, d)
        return best

    def verdict(self, addr, day, tolerance=0):
        """'verified' (version in force holds it), 'tolerance' (a version within tolerance days holds it),
        'other_time' (some version holds it, but further away), or 'never'."""
        held = self.holding(addr)
        if not held:
            return "never"
        if self.versions[self.in_force(day)][2] in held:
            return "verified"
        d = self.distance(addr, day)
        return "tolerance" if d is not None and d <= tolerance else "other_time"

    def allowed_prefixes(self, today, tolerance):
        """Union of every version in force at some point in [today - tolerance, today]."""
        out = set()
        for i, (first, _, cid) in enumerate(self.versions):
            end = self.firsts[i + 1] - 1 if i + 1 < len(self.versions) else today
            if end >= today - tolerance and first <= today:
                out.update(self.contents[cid])
        return sorted(out)
