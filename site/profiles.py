"""Build, check and serialize Quiet DNS configuration profiles (.mobileconfig)."""

from __future__ import annotations

import ipaddress
import plistlib
from typing import Any
from urllib.parse import urlparse

from .settings import RESOLVERS, Settings

# Every Quiet DNS profile has the same identity and the same display name. iOS treats a profile
# with these identifiers and a higher PayloadVersion as an update to the one already installed,
# so changing a filter, pausing, or resuming edits the existing entry instead of adding another.
PROFILE_ID = "com.quiet.dns.profile"
PROFILE_UUID = "A7C3E912-5B64-4D8F-A120-9E6B3F7C2045"
DNS_ID = "com.quiet.dns.settings"
DNS_UUID = "F5D2B0C1-7A83-4E96-9B21-6C8D4F0A2E17"
DISPLAY_NAME = "Quiet DNS"

REMOVE_HINT = "You can remove this profile any time in Settings > General > VPN & Device Management."

FILTER_TEXT = {
    "default": "blocks ads, trackers and phishing sites",
    "family": "blocks ads, trackers, phishing sites and adult websites, and turns on safe search",
    "unfiltered": "does not block ads or trackers",
}

# While paused, the DNS settings stay in the profile, and iOS is told never to connect them.
PAUSED_RULES = [{"Action": "Disconnect"}]


class ProfileError(ValueError):
    """A profile failed its checks."""


def profile_name(s: Settings) -> str:
    return DISPLAY_NAME


def summary(s: Settings) -> str:
    if not s.enabled:
        return "Paused. Lookups use your network's normal DNS until Quiet DNS is turned back on."
    return f"Encrypted DNS through AdGuard DNS. It {FILTER_TEXT[s.resolver_key()]}."


def consent_text(s: Settings) -> str:
    """Shown to the person when they install the profile, so it has to match the settings."""
    if not s.enabled:
        return ("Quiet DNS is paused, so lookups from this device use your network's normal DNS. "
                "Install Quiet DNS again to turn it back on. " + REMOVE_HINT)
    text = (f"Lookups from this device go over an encrypted connection to AdGuard DNS, which "
            f"{FILTER_TEXT[s.resolver_key()]}. Your network can no longer see the domain names this "
            "device looks up, but AdGuard DNS can.")
    if s.failover:
        text += (" If AdGuard DNS can't be reached, lookups fall back to your network's DNS, "
                 "which is not encrypted.")
    return text + " " + REMOVE_HINT


def _dns_payload(s: Settings, version: int) -> dict[str, Any]:
    r = s.resolver()
    dns: dict[str, Any] = {"DNSProtocol": "TLS" if s.use_tls else "HTTPS"}
    if s.use_tls:
        dns["ServerName"] = r["dot"]
    else:
        dns["ServerURL"] = r["doh"]
    if s.bootstrap_ips:
        dns["ServerAddresses"] = list(r["ipv4"]) + list(r["ipv6"])
    if s.failover:
        dns["AllowFailover"] = True

    payload: dict[str, Any] = {
        "DNSSettings": dns,
        "PayloadDescription": summary(s),
        "PayloadDisplayName": DISPLAY_NAME,
        "PayloadIdentifier": DNS_ID,
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadUUID": DNS_UUID,
        "PayloadVersion": version,
    }
    if not s.enabled:
        payload["OnDemandRules"] = [dict(rule) for rule in PAUSED_RULES]
    return payload


def build_profile(s: Settings, version: int) -> dict[str, Any]:
    """Return the profile as a plist-ready dict. Pausing keeps the DNS payload and adds a rule."""
    return {
        "ConsentText": {"default": consent_text(s)},
        "PayloadContent": [_dns_payload(s, version)],
        "PayloadDescription": summary(s),
        "PayloadDisplayName": DISPLAY_NAME,
        "PayloadIdentifier": PROFILE_ID,
        "PayloadOrganization": "Quiet",
        "PayloadRemovalDisallowed": False,  # the person can always remove the profile
        "PayloadScope": "System",
        "PayloadType": "Configuration",
        "PayloadUUID": PROFILE_UUID,
        "PayloadVersion": version,
    }


def to_bytes(profile: dict[str, Any]) -> bytes:
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


def _resolver_for_host(host: Any) -> dict[str, Any] | None:
    for r in RESOLVERS.values():
        if host in (urlparse(r["doh"]).hostname, r["dot"]):
            return r
    return None


def _check_dns_payload(payload: dict[str, Any], version: Any) -> list[str]:
    problems: list[str] = []
    if payload.get("PayloadType") != "com.apple.dnsSettings.managed":
        problems.append("DNS payload has the wrong PayloadType")
    if payload.get("PayloadIdentifier") != DNS_ID or payload.get("PayloadUUID") != DNS_UUID:
        problems.append("DNS payload identifier or UUID is not the Quiet DNS slot")
    if payload.get("PayloadVersion") != version:
        problems.append("DNS payload and profile PayloadVersion differ")

    dns = payload.get("DNSSettings")
    if not isinstance(dns, dict):
        return problems + ["DNSSettings is missing"]

    protocol = dns.get("DNSProtocol")
    if protocol == "HTTPS":
        url = str(dns.get("ServerURL", ""))
        host = urlparse(url).hostname
        if not url.startswith("https://"):
            problems.append("ServerURL must start with https://")
        if "ServerName" in dns:
            problems.append("ServerName is only used with TLS")
    elif protocol == "TLS":
        host = dns.get("ServerName")
        if "ServerURL" in dns:
            problems.append("ServerURL is only used with HTTPS")
    else:
        return problems + [f"unknown DNSProtocol {protocol!r}"]

    resolver = _resolver_for_host(host)
    if resolver is None:
        problems.append(f"{host!r} is not an AdGuard DNS host")

    if "ServerAddresses" in dns:
        addresses = dns["ServerAddresses"]
        if not isinstance(addresses, list):
            problems.append("ServerAddresses must be an array")
        else:
            for address in addresses:
                try:
                    ipaddress.ip_address(address)
                except (ValueError, TypeError):
                    problems.append(f"invalid bootstrap address {address!r}")
            # Catches a copy-paste error such as the family hostname with the default IPs.
            if resolver is not None and not set(addresses) <= set(resolver["ipv4"] + resolver["ipv6"]):
                problems.append("bootstrap addresses do not belong to this resolver")

    if "AllowFailover" in dns and not isinstance(dns["AllowFailover"], bool):
        problems.append("AllowFailover must be a boolean")
    return problems


def check_profile(data: dict[str, Any]) -> list[str]:
    """Return the problems found in a profile. An empty list means it passes."""
    problems: list[str] = []
    if data.get("PayloadIdentifier") != PROFILE_ID:
        problems.append("PayloadIdentifier is not the Quiet DNS profile identifier")
    if data.get("PayloadUUID") != PROFILE_UUID:
        problems.append("PayloadUUID is not the Quiet DNS profile UUID")
    if data.get("PayloadDisplayName") != DISPLAY_NAME:
        problems.append("PayloadDisplayName must be the one Quiet DNS name, so the entry doesn't change")
    if data.get("PayloadType") != "Configuration":
        problems.append("PayloadType must be Configuration")
    if data.get("PayloadRemovalDisallowed") is not False:
        problems.append("PayloadRemovalDisallowed must be false so the person can remove the profile")

    version = data.get("PayloadVersion")
    if not isinstance(version, int) or isinstance(version, bool):
        problems.append("PayloadVersion must be an integer")

    consent = data.get("ConsentText")
    if not isinstance(consent, dict) or not str(consent.get("default", "")).strip():
        problems.append("ConsentText must include a non-empty default string")

    content = data.get("PayloadContent")
    if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict):
        return problems + ["a Quiet DNS profile needs exactly one DNS payload"]

    payload = content[0]
    problems.extend(_check_dns_payload(payload, version))
    if "OnDemandRules" in payload and payload["OnDemandRules"] != PAUSED_RULES:
        problems.append("OnDemandRules is only used to pause Quiet DNS")
    return problems
