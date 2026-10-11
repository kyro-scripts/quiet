"""Command line for Quiet DNS.

    python3 -m quiet presets                       # the four preset profiles, into dist/
    python3 -m quiet profile -o my.mobileconfig    # one profile from individual settings
    python3 -m quiet wg my.conf -o quiet.conf      # your WireGuard config, pointed at AdGuard DNS

Run `python3 -m quiet <command> --help` for every option.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

from . import profiles, signing, wireguard
from .settings import RESOLVERS, Settings

PROJECT = Path(__file__).resolve().parent.parent

PRESETS: list[tuple[str, Settings]] = [
    ("Quiet-DNS-Standard.mobileconfig", Settings()),
    ("Quiet-DNS-Family.mobileconfig", Settings(block_adult=True)),
    ("Quiet-DNS-Unfiltered.mobileconfig", Settings(block_ads=False)),
    ("Quiet-DNS-Paused.mobileconfig", Settings(enabled=False)),
]


def _add_build_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--version", type=int, default=None,
                   help="PayloadVersion. Default: the current Unix time, so every new build "
                        "replaces the one installed before it.")
    p.add_argument("--sign", nargs=2, metavar=("CERT_PEM", "KEY_PEM"),
                   help="sign with your own certificate and private key")
    p.add_argument("--chain", type=Path, metavar="PEM",
                   help="intermediate certificates to include when signing")


def _build(s: Settings, version: int) -> bytes:
    data = profiles.build_profile(s, version)
    problems = profiles.check_profile(data)
    if problems:
        raise profiles.ProfileError(f"{data['PayloadDisplayName']}: {'; '.join(problems)}")
    return profiles.to_bytes(data)


def _write(path: Path, raw: bytes, sign_args: list[str] | None, chain: Path | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if sign_args:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / path.name
            src.write_bytes(raw)
            signing.sign_profile(src, path, Path(sign_args[0]), Path(sign_args[1]), chain)
    else:
        path.write_bytes(raw)
    print(f"wrote {path} ({'signed' if sign_args else 'unsigned'})")


def _inside_project(path: Path) -> bool:
    try:
        path.resolve().relative_to(PROJECT)
        return True
    except ValueError:
        return False


def _cmd_presets(args: argparse.Namespace) -> int:
    version = args.version or int(time.time())
    # Build and check every preset before writing anything, so a failure never leaves a mix of files.
    built = [(args.out / name, _build(s, version)) for name, s in PRESETS]
    for path, raw in built:
        _write(path, raw, args.sign, args.chain)
    return 0


def _cmd_profile(args: argparse.Namespace) -> int:
    s = Settings(
        enabled=not args.off,
        block_ads=not args.no_ads,
        block_adult=args.adult,
        use_tls=args.tls,
        bootstrap_ips=not args.no_bootstrap,
        failover=args.failover,
    )
    raw = _build(s, args.version or int(time.time()))
    _write(args.output, raw, args.sign, args.chain)
    return 0


def _cmd_wg(args: argparse.Namespace) -> int:
    if _inside_project(args.output):
        raise OSError("refusing to write a WireGuard config inside the Quiet project folder; "
                      "choose a location outside it")
    if args.output.exists() and not args.force:
        raise OSError(f"{args.output} already exists; use --force to replace it")

    text = args.config.read_text(encoding="utf-8")
    old = wireguard.current_dns(text)
    new = wireguard.retarget_dns(text, args.mode)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(new)
    os.chmod(args.output, 0o600)

    r = RESOLVERS[args.mode]
    print(f"wrote {args.output} (readable only by you)")
    print(f"DNS was:  {', '.join(old) or '(not set)'}")
    print(f"DNS is:   {', '.join(list(r['ipv4']) + list(r['ipv6']))}")
    print("The private key was not printed. Keep this file private and don't upload it anywhere.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m quiet",
                                     description="Build Quiet DNS profiles and WireGuard configs.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("presets", help="build the four preset profiles")
    p.add_argument("--out", type=Path, default=PROJECT / "dist", help="output folder (default: dist/)")
    _add_build_options(p)
    p.set_defaults(func=_cmd_presets)

    c = sub.add_parser("profile", help="build one profile from individual settings")
    c.add_argument("-o", "--output", type=Path, required=True, help="file to write")
    c.add_argument("--off", action="store_true",
                   help="pause Quiet DNS; the profile stays installed but iPhone stops using its DNS settings")
    c.add_argument("--no-ads", action="store_true", help="don't block ads and trackers")
    c.add_argument("--adult", action="store_true",
                   help="block adult sites and turn on safe search (this includes ad blocking)")
    c.add_argument("--tls", action="store_true", help="use DNS over TLS (port 853) instead of HTTPS")
    c.add_argument("--no-bootstrap", action="store_true", help="leave AdGuard's IP addresses out")
    c.add_argument("--failover", action="store_true",
                   help="fall back to the network's DNS if AdGuard can't be reached (iOS/macOS 26+)")
    _add_build_options(c)
    c.set_defaults(func=_cmd_profile)

    w = sub.add_parser("wg", help="point a WireGuard config's DNS at AdGuard DNS")
    w.add_argument("config", type=Path, help="your own WireGuard .conf file")
    w.add_argument("-o", "--output", type=Path, required=True,
                   help="where to write the new config (must be outside this project)")
    w.add_argument("--mode", choices=list(RESOLVERS), default="default",
                   help="which AdGuard resolver to use (default: default)")
    w.add_argument("--force", action="store_true", help="replace the output file if it exists")
    w.set_defaults(func=_cmd_wg)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (profiles.ProfileError, signing.SigningError, wireguard.WireGuardError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
