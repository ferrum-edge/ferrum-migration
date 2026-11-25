"""Source platform translators. Each exposes ``translate(text, fmt, ctx) -> Plan``."""

from __future__ import annotations

from . import envoy, istio, kong, nginx, traefik

SOURCES = {
    "kong": kong,
    "nginx": nginx,
    "traefik": traefik,
    "envoy": envoy,
    "istio": istio,
}

DESCRIPTIONS = {
    "kong": "Kong Gateway declarative config (DB-less kong.yml or decK dump; YAML/JSON)",
    "nginx": "NGINX OSS http reverse-proxy configuration (nginx.conf syntax, one file, includes not followed)",
    "traefik": "Traefik OSS dynamic configuration, file provider http section (YAML/TOML/JSON)",
    "envoy": "Envoy v3 static bootstrap with static_resources HTTP listeners (YAML/JSON)",
    "istio": "Istio networking CRDs: Gateway, VirtualService, DestinationRule, ServiceEntry (multi-doc YAML)",
}

__all__ = ["SOURCES", "DESCRIPTIONS"]
