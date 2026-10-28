#!/usr/bin/env python3
"""Replace Cowrie's default persona in fs.pickle with a consistent custom one.

Cowrie 3.x stores the fake filesystem *and* the contents of small files
(/etc/passwd, /etc/hostname, /proc/version...) in one pickle. Default values
such as the user "phil" and hostname "svr04" are well-known honeypot
fingerprints, so this script rewrites them consistently everywhere.

Usage (run on the honeypot host; the input is Cowrie's own pinned file):
    python3 -I customize_fs.py <default fs.pickle>                 # dry run
    python3 -I customize_fs.py <default fs.pickle> <out fs.pickle>  # write

Node layout: [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
  type 1 = directory (contents = list of child nodes)
  type 2 = file      (contents = bytes, or None)
"""

import copy
import pickle
import re
import sys

# --- Persona -----------------------------------------------------------------
HOSTNAME = "prod-db-02"
ADMIN_USER = "dbadmin"
ADMIN_GECOS = "Database Admin,,,"
PG_UID, PG_GID = 108, 115

# Default strings to replace in every file's contents (order matters).
REPLACEMENTS = [
    (rb"Phil California,,,", ADMIN_GECOS.encode()),
    (rb"\bphil\b", ADMIN_USER.encode()),
    (rb"\bsvr04\b", HOSTNAME.encode()),
    (rb"6\.1\.0-21-amd64", b"6.1.0-28-amd64"),
    (rb"6\.1\.90-1 \(2024-05-03\)", b"6.1.119-1 (2024-11-22)"),
]
FINGERPRINTS = [pattern for pattern, _ in REPLACEMENTS]

# Extra lines appended to account files so a "database server" has a database user.
EXTRA_LINES = {
    "/etc/passwd": f"postgres:x:{PG_UID}:{PG_GID}:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n",
    "/etc/group": f"postgres:x:{PG_GID}:\nssl-cert:x:{PG_GID - 1}:postgres\n",
    "/etc/shadow": "postgres:*:19800:0:99999:7:::\n",
}

NAME, TYPE, UID, GID, SIZE, MODE, CTIME, CONTENTS = range(8)
T_DIR, T_FILE = 1, 2


def walk(node, path=""):
    """Yield (path, node) for every entry in the tree."""
    here = path.rstrip("/") + "/" + node[NAME] if path else "/"
    yield here, node
    if node[TYPE] == T_DIR:
        for child in node[CONTENTS]:
            yield from walk(child, here)


def find(root, path):
    node = root
    for part in path.strip("/").split("/"):
        node = next((c for c in node[CONTENTS] if c[NAME] == part), None)
        if node is None:
            return None
    return node


def label(pattern):
    """Readable form of a regex pattern for printing."""
    return pattern.decode().replace("\\b", "").replace("\\", "")


def scan(root, title):
    print(f"== {title} ==")
    hits = 0
    for path, node in walk(root):
        blobs = [node[NAME].encode()]
        if node[TYPE] == T_FILE and isinstance(node[CONTENTS], bytes):
            blobs.append(node[CONTENTS])
        found = sorted({label(p) for p in FINGERPRINTS if any(re.search(p, b) for b in blobs)})
        if found:
            hits += 1
            print(f"  {path}: {', '.join(found)}")
    print(f"  ({hits} entries)\n")
    return hits


def apply(root):
    changes = []
    # 1. Rewrite file contents and fix the size field.
    for path, node in walk(root):
        if node[TYPE] == T_FILE and isinstance(node[CONTENTS], bytes):
            new = node[CONTENTS]
            for pattern, repl in REPLACEMENTS:
                new = re.sub(pattern, repl, new)
            if path in EXTRA_LINES and b"postgres:" not in new:
                new = new.rstrip(b"\n") + b"\n" + EXTRA_LINES[path].encode()
            if new != node[CONTENTS]:
                node[CONTENTS], node[SIZE] = new, len(new)
                changes.append(f"edited   {path}")

    # 2. Rename /home/phil -> /home/<admin>.
    home = find(root, "/home/phil")
    if home is not None:
        home[NAME] = ADMIN_USER
        changes.append(f"renamed  /home/phil -> /home/{ADMIN_USER}")

    # 3. Add /var/lib/postgresql owned by postgres (copying /home's metadata).
    var_lib = find(root, "/var/lib")
    if var_lib is not None and find(root, "/var/lib/postgresql") is None:
        template = find(root, "/home")
        pg = [ "postgresql", T_DIR, PG_UID, PG_GID, 4096, 0o40755, template[CTIME], [], None, None]
        pg[CONTENTS].append(["15", T_DIR, PG_UID, PG_GID, 4096, 0o40755, template[CTIME], [], None, None])
        var_lib[CONTENTS].append(pg)
        changes.append("added    /var/lib/postgresql/15")

    print("== changes ==")
    for line in changes:
        print("  " + line)
    print()


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    with open(sys.argv[1], "rb") as f:
        original = pickle.load(f)  # trusted: Cowrie's own file from a pinned image

    scan(original, "default fingerprints found")
    custom = copy.deepcopy(original)
    apply(custom)
    remaining = scan(custom, "fingerprints remaining after changes")

    for path in ("/etc/passwd", "/etc/hostname"):
        node = find(custom, path)
        if node is not None:
            print(f"== {path} (new) ==\n{node[CONTENTS].decode(errors='replace')}")

    if len(sys.argv) == 3:
        if remaining:
            sys.exit("Refusing to write: fingerprints remain (see above).")
        with open(sys.argv[2], "wb") as f:
            pickle.dump(custom, f)
        print(f"Wrote {sys.argv[2]}")
    else:
        print("Dry run only. Pass an output path to write the new fs.pickle.")


if __name__ == "__main__":
    main()
