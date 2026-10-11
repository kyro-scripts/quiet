"""Point a WireGuard config's DNS at AdGuard DNS.

This runs on your own computer, on your own config file. It never sends the config anywhere,
and it never prints the PrivateKey. Error messages avoid echoing config lines for the same reason.
"""

from __future__ import annotations

from typing import Any

from .settings import RESOLVERS


class WireGuardError(ValueError):
    """The WireGuard config can't be used."""


def _key(line: str) -> str | None:
    """The lowercase key of a 'Key = value' line, or None for comments, headers and blanks."""
    stripped = line.strip()
    if not stripped or stripped[0] in "#;" or "=" not in stripped:
        return None
    return stripped.split("=", 1)[0].strip().lower()


def _split(text: str) -> list[list[Any]]:
    """Split a config into [section_name, lines] pairs. Each section keeps its own header line."""
    sections: list[list[Any]] = [[None, []]]
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            sections.append([stripped[1:-1].strip().lower(), [line]])
        else:
            sections[-1][1].append(line)
    return sections


def current_dns(text: str) -> list[str]:
    """The DNS addresses the config currently uses, for reporting only."""
    for name, lines in _split(text):
        if name == "interface":
            for line in lines:
                if _key(line) == "dns":
                    value = line.split("=", 1)[1]
                    return [v.strip() for v in value.split(",") if v.strip()]
    return []


def retarget_dns(text: str, mode: str) -> str:
    """Return the config with its [Interface] DNS line set to AdGuard DNS for the given mode."""
    if mode not in RESOLVERS:
        raise WireGuardError(f"unknown mode {mode!r}; choose one of: {', '.join(RESOLVERS)}")

    sections = _split(text)
    interfaces = [s for s in sections if s[0] == "interface"]
    peers = [s for s in sections if s[0] == "peer"]
    if len(interfaces) != 1:
        raise WireGuardError("the config needs exactly one [Interface] section")
    if not peers:
        raise WireGuardError("the config needs at least one [Peer] section")

    body = interfaces[0][1]
    if not any(_key(line) == "privatekey" for line in body):
        raise WireGuardError("the [Interface] section has no PrivateKey")

    r = RESOLVERS[mode]
    new_line = "DNS = " + ", ".join(list(r["ipv4"]) + list(r["ipv6"]))
    kept = [line for line in body if _key(line) != "dns"]
    address_at = next((i for i, line in enumerate(kept) if _key(line) == "address"), None)
    if address_at is None:
        kept.append(new_line)
    else:
        kept.insert(address_at + 1, new_line)  # keep DNS next to Address, where people expect it

    interfaces[0][1] = kept
    return "\n".join(line for _, lines in sections for line in lines) + "\n"
