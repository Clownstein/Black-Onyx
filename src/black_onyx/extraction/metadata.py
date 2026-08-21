"""Metadata extraction from HTML and plain text using centralized patterns."""

from __future__ import annotations

import logging
import re
from typing import Any

from bs4 import BeautifulSoup

from black_onyx.extraction.patterns import (
    ADULT_SITE_PATTERNS,
    CRYPTO_FIELD_MAP,
    CRYPTO_PATTERNS,
    DISCORD_INVITE_PATTERN,
    EMAIL_PATTERN,
    FACEBOOK_ANALYTICS_PATTERN,
    GOOGLE_ANALYTICS_PATTERN,
    GPG_KEY_PATTERN,
    IRC_PATTERN,
    PAYPAL_LINK_PATTERN,
    PHONE_PATTERN,
    SOCIAL_MEDIA_PATTERNS,
    SSH_KEY_PATTERN,
    WHATSAPP_INVITE_PATTERN,
    IP_PATTERN,
)

logger = logging.getLogger(__name__)


def extract_metadata_from_html(html: str) -> dict[str, Any]:
    """Extract metadata from HTML content.

    Extracts: title, meta tags, emails, phones, URLs, image URLs, social profiles,
    crypto addresses, IP addresses, analytics IDs, site name, and various invite links.

    Args:
        html: HTML content string.

    Returns:
        Dict with extracted metadata, compatible with DataModel fields.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Title
    title = soup.title.string.strip() if soup.title and soup.title.string else None

    # Meta tags
    meta_tags: dict[str, str] = {}
    for meta_tag in soup.find_all("meta", attrs={"name": True, "content": True}):
        meta_tags[str(meta_tag.attrs["name"])] = str(meta_tag.attrs["content"])
    # Also capture OpenGraph and Twitter meta tags
    for meta_tag in soup.find_all("meta", attrs={"property": True, "content": True}):
        meta_tags[str(meta_tag.attrs["property"])] = str(meta_tag.attrs["content"])

    # URLs and image URLs
    urls = [a["href"] for a in soup.find_all("a", href=True)]
    image_urls = [img["src"] for img in soup.find_all("img", src=True)]

    # Basic entity extraction from the raw HTML
    email_matches = EMAIL_PATTERN.findall(html)
    phone_matches = PHONE_PATTERN.findall(html)
    ip_matches = IP_PATTERN.findall(html)
    google_analytics_matches = GOOGLE_ANALYTICS_PATTERN.findall(html)
    facebook_analytics_matches = FACEBOOK_ANALYTICS_PATTERN.findall(html)

    # Social media profiles
    social_profiles: dict[str, list[str]] = {}
    for platform, pattern in SOCIAL_MEDIA_PATTERNS.items():
        matches = pattern.findall(html)
        if matches:
            # findall with groups returns tuples; join them
            cleaned = []
            for m in matches:
                if isinstance(m, tuple):
                    cleaned.append("".join(m))
                else:
                    cleaned.append(m)
            social_profiles[platform] = cleaned

    # Crypto addresses
    cryptos: dict[str, list[str]] = {}
    for name, pattern in CRYPTO_PATTERNS.items():
        matches = pattern.findall(html)
        if matches:
            cleaned = []
            for m in matches:
                if isinstance(m, tuple):
                    cleaned.append("".join(m))
                else:
                    cleaned.append(m)
            cryptos[name] = cleaned

    # Communication patterns
    irc_matches = IRC_PATTERN.findall(html)
    gpg_matches = GPG_KEY_PATTERN.findall(html)
    ssh_matches = SSH_KEY_PATTERN.findall(html)
    discord_matches = DISCORD_INVITE_PATTERN.findall(html)
    whatsapp_matches = WHATSAPP_INVITE_PATTERN.findall(html)
    paypal_matches = PAYPAL_LINK_PATTERN.findall(html)

    # Adult site URLs
    adult_matches: dict[str, list[str]] = {}
    for name, pattern in ADULT_SITE_PATTERNS.items():
        matches = pattern.findall(html)
        if matches:
            cleaned = []
            for m in matches:
                if isinstance(m, tuple):
                    cleaned.append("".join(m))
                else:
                    cleaned.append(m)
            adult_matches[name] = cleaned

    # Site name
    site_name = (
        meta_tags.get("og:site_name")
        or meta_tags.get("application-name")
        or meta_tags.get("twitter:site")
    )

    return {
        "title": title,
        "meta": meta_tags,
        "emails": email_matches,
        "phone_numbers": phone_matches,
        "urls": urls,
        "image_urls": image_urls,
        "social_profiles": social_profiles,
        "cryptos": cryptos,
        "ip_addresses": ip_matches,
        "google_analytics_ids": google_analytics_matches,
        "facebook_analytics_ids": facebook_analytics_matches,
        "irc_addresses": irc_matches,
        "gpg_keys": gpg_matches,
        "ssh_keys": ssh_matches,
        "discord_invite": discord_matches,
        "whatsapp_invite": whatsapp_matches,
        "paypal_link": paypal_matches,
        "site_name": site_name,
        **{k: v for k, v in adult_matches.items()},
    }


def extract_metadata_from_text(text: str) -> dict[str, Any]:
    """Extract metadata from plain text (non-HTML).

    Runs regex patterns for emails, phones, IPs, crypto, social, analytics,
    and communication patterns on the raw text.

    Args:
        text: Plain text string.

    Returns:
        Dict with extracted metadata, compatible with DataModel fields.
    """
    email_matches = EMAIL_PATTERN.findall(text)
    phone_matches = PHONE_PATTERN.findall(text)
    ip_matches = IP_PATTERN.findall(text)
    google_analytics_matches = GOOGLE_ANALYTICS_PATTERN.findall(text)
    facebook_analytics_matches = FACEBOOK_ANALYTICS_PATTERN.findall(text)

    # Social media profiles
    social_profiles: dict[str, list[str]] = {}
    for platform, pattern in SOCIAL_MEDIA_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            cleaned = []
            for m in matches:
                if isinstance(m, tuple):
                    cleaned.append("".join(m))
                else:
                    cleaned.append(m)
            social_profiles[platform] = cleaned

    # Crypto addresses
    cryptos: dict[str, list[str]] = {}
    for name, pattern in CRYPTO_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            cleaned = []
            for m in matches:
                if isinstance(m, tuple):
                    cleaned.append("".join(m))
                else:
                    cleaned.append(m)
            cryptos[name] = cleaned

    # Communication patterns
    irc_matches = IRC_PATTERN.findall(text)
    gpg_matches = GPG_KEY_PATTERN.findall(text)
    ssh_matches = SSH_KEY_PATTERN.findall(text)
    discord_matches = DISCORD_INVITE_PATTERN.findall(text)
    whatsapp_matches = WHATSAPP_INVITE_PATTERN.findall(text)
    paypal_matches = PAYPAL_LINK_PATTERN.findall(text)

    # Adult site URLs
    adult_matches: dict[str, list[str]] = {}
    for name, pattern in ADULT_SITE_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            cleaned = []
            for m in matches:
                if isinstance(m, tuple):
                    cleaned.append("".join(m))
                else:
                    cleaned.append(m)
            adult_matches[name] = cleaned

    # URLs: simple extraction from plain text
    url_pattern = re.compile(r"https?://[^\s<>'\"]+")
    urls = url_pattern.findall(text)

    return {
        "emails": email_matches,
        "phone_numbers": phone_matches,
        "urls": urls,
        "ip_addresses": ip_matches,
        "google_analytics_ids": google_analytics_matches,
        "facebook_analytics_ids": facebook_analytics_matches,
        "social_profiles": social_profiles,
        "cryptos": cryptos,
        "irc_addresses": irc_matches,
        "gpg_keys": gpg_matches,
        "ssh_keys": ssh_matches,
        "discord_invite": discord_matches,
        "whatsapp_invite": whatsapp_matches,
        "paypal_link": paypal_matches,
        **{k: v for k, v in adult_matches.items()},
    }


def map_crypto_to_fields(cryptos: dict[str, list[str]]) -> dict[str, list[str]]:
    """Map crypto pattern names to DataModel field names.

    Args:
        cryptos: Dict from extract_metadata (e.g. {"bitcoin": ["1abc..."], ...}).

    Returns:
        Dict mapping DataModel field names to lists of addresses.
    """
    result: dict[str, list[str]] = {}
    for crypto_name, addresses in cryptos.items():
        field_name = CRYPTO_FIELD_MAP.get(crypto_name)
        if field_name:
            result[field_name] = addresses
    return result
