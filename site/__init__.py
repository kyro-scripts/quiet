"""Quiet DNS: builds iPhone and Mac profiles that turn on encrypted, filtered DNS.

Modules:
    settings   - the toggles, and how each one maps to an AdGuard DNS resolver
    profiles   - builds, checks and serializes the .mobileconfig files
    signing    - optional signing with your own certificate (openssl)
    wireguard  - points a WireGuard config's DNS at AdGuard DNS, on your computer
"""

__version__ = "2.2.0"
