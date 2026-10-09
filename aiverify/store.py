"""Versioned store of vendor IP lists: content-addressed bodies plus the periods each body was observed.

Layout: {"lists": {name: {"contents": {cid: [prefix, ...]},
                          "versions": [[first_seen, last_seen, cid, source], ...]}}}
Times are UTC ISO-8601 strings. Consecutive observations of the same content extend one version, so a list
that flaps A -> B -> A keeps three versions.
"""
import datetime
import hashlib
import json
import os

from .ranges import VersionedList


def content_id(prefixes):
    return hashlib.sha256(json.dumps(sorted(prefixes)).encode()).hexdigest()[:16]


def load(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"lists": {}}


def save(store, path):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(store, fh, separators=(",", ":"))
    os.replace(tmp, path)


def observe(store, name, prefixes, when, source):
    """Record that list `name` had content `prefixes` at time `when` (ISO string). Returns True if it is a
    new version. Observations must arrive in time order per list."""
    entry = store["lists"].setdefault(name, {"contents": {}, "versions": []})
    cid = content_id(prefixes)
    entry["contents"].setdefault(cid, sorted(prefixes))
    versions = entry["versions"]
    if versions and versions[-1][2] == cid:
        versions[-1][1] = max(versions[-1][1], when)
        return False
    if versions and when < versions[-1][1]:
        raise ValueError(f"{name}: observation {when} is older than the latest one {versions[-1][1]}")
    versions.append([when, when, cid, source])
    return True


def wayback_time(ts14):
    return f"{ts14[:4]}-{ts14[4:6]}-{ts14[6:8]}T{ts14[8:10]}:{ts14[10:12]}:{ts14[12:14]}Z"


def import_snapshots(store, snapshots):
    """Import the analysis format {name: {"snapshots": [[ts14, digest]], "bodies": {digest: [...]}}}."""
    for name, entry in snapshots.items():
        for ts, digest in sorted(entry["snapshots"]):
            observe(store, name, entry["bodies"][digest], wayback_time(ts), "wayback:" + ts)


def day(iso):
    return datetime.date.fromisoformat(iso[:10]).toordinal()


def versioned(store, name):
    entry = store["lists"][name]
    versions = [(day(f), day(l), cid) for f, l, cid, _ in entry["versions"]]
    return VersionedList(versions, entry["contents"])


def all_versioned(store):
    return {name: versioned(store, name) for name, entry in store["lists"].items() if entry["versions"]}
