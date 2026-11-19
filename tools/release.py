"""Publish a Pure Guard release on GitHub (the Winter Air scheme, smaller).

    python tools/release.py          # build the release APK, then make GitHub release v<version>
    python tools/release.py --notes  # print this version's bullets (build.sh puts them in the app)

The version lives in app/AndroidManifest.xml (versionName + versionCode); the words live in
CHANGELOG.md under "## <versionName> — <date>". Every installed app reads
    https://github.com/DeadEyeZJhin/pure-guard/releases/latest/download/update.json
which GitHub always points at the newest release. update.json names the APK by its own tag.
Before a release: bump versionCode by one (Android compares it), write the CHANGELOG bullets,
commit and push.
"""
import hashlib, json, os, re, shutil, subprocess, sys
from datetime import date

REPO = "DeadEyeZJhin/pure-guard"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def version():
    m = open(os.path.join(ROOT, "app", "AndroidManifest.xml"), encoding="utf-8").read()
    return (re.search(r'versionName="([^"]+)"', m).group(1), int(re.search(r'versionCode="(\d+)"', m).group(1)))


def notes(name):
    """Bullets under '## <name>' in CHANGELOG.md; a bullet may wrap onto indented lines."""
    text = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
    m = re.search(rf"^## {re.escape(name)}\b.*$", text, re.M)
    if not m:
        return []
    body = text[m.end():]
    nxt = re.search(r"^## ", body, re.M)
    out = []
    for line in body[: nxt.start() if nxt else len(body)].splitlines():
        if line.startswith("- "):
            out.append(line[2:].strip())
        elif out and line[:1].isspace() and line.strip():
            out[-1] += " " + line.strip()
    return out


def main():
    name, code = version()
    bullets = notes(name)
    if "--notes" in sys.argv:
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")  # Windows would write cp1252
        print("\n".join("• " + b.replace("**", "") for b in bullets))
        return
    if not bullets:
        raise SystemExit(f"CHANGELOG.md needs bullets under '## {name}' first: they are What's new on every phone.")
    subprocess.run(["bash", "build.sh", "release"], check=True, cwd=ROOT)
    out = os.path.join(ROOT, "out", "release")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    tag, asset = "v" + name, f"PureGuard-{name}.apk"
    shutil.copy(os.path.join(ROOT, "out", "PureGuard.apk"), os.path.join(out, asset))
    data = open(os.path.join(out, asset), "rb").read()
    manifest = {
        "app": "Pure Guard", "versionName": name, "versionCode": code,
        "releasedAt": date.today().isoformat(), "notes": bullets,
        "apkUrl": f"https://github.com/{REPO}/releases/download/{tag}/{asset}",
        "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
    }
    with open(os.path.join(out, "update.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    with open(os.path.join(out, "notes.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join("- " + b for b in bullets) + "\n")
    subprocess.run(["gh", "release", "create", tag, os.path.join(out, asset), os.path.join(out, "update.json"),
                    "--repo", REPO, "--title", f"Pure Guard {name}", "--notes-file", os.path.join(out, "notes.md")],
                   check=True, cwd=ROOT)
    print(f"Pure Guard {name} (build {code}) is out: {manifest['apkUrl']}")


if __name__ == "__main__":
    main()
