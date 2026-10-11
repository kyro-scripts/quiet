"""The settings Quiet DNS exposes, and how each one maps to the resolver iOS will use."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# AdGuard DNS endpoints and bootstrap IP addresses, from https://adguard-dns.io/en/public-dns.html
# "doh" is DNS over HTTPS, "dot" is the hostname used for DNS over TLS (port 853).
# Bootstrap IPs let the device reach the resolver before DNS is switched over.
RESOLVERS: dict[str, dict[str, Any]] = {
    "default": {
        "doh": "https://dns.adguard-dns.com/dns-query",
        "dot": "dns.adguard-dns.com",
        "ipv4": ["94.140.14.14", "94.140.15.15"],
        "ipv6": ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
    },
    "family": {
        "doh": "https://family.adguard-dns.com/dns-query",
        "dot": "family.adguard-dns.com",
        "ipv4": ["94.140.14.15", "94.140.15.16"],
        "ipv6": ["2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"],
    },
    "unfiltered": {
        "doh": "https://unfiltered.adguard-dns.com/dns-query",
        "dot": "unfiltered.adguard-dns.com",
        "ipv4": ["94.140.14.140", "94.140.14.141"],
        "ipv6": ["2a10:50c0::1:ff", "2a10:50c0::2:ff"],
    },
}


@dataclass(frozen=True)
class Settings:
    """Every toggle the website and CLI expose. The defaults give the Standard profile."""

    enabled: bool = True        # False pauses Quiet DNS; the profile stays installed
    block_ads: bool = True      # block ads and trackers
    block_adult: bool = False   # block adult sites and turn on safe search (uses the family resolver)
    use_tls: bool = False       # DNS over TLS (port 853) instead of DNS over HTTPS
    bootstrap_ips: bool = True  # include AdGuard's IPs so the resolver is reachable before DNS switches
    failover: bool = False      # if AdGuard can't be reached, fall back to the network's DNS (iOS/macOS 26+)

    def resolver_key(self) -> str:
        """Which AdGuard resolver these settings need. Adult blocking always includes ad blocking."""
        if self.block_adult:
            return "family"
        if self.block_ads:
            return "default"
        return "unfiltered"

    def resolver(self) -> dict[str, Any]:
        return RESOLVERS[self.resolver_key()]
