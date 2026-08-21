"""All compiled regex patterns for entity extraction.

Patterns are compiled once at module import for performance.
This is the single source of truth for all regex patterns used in the project.
"""

from __future__ import annotations

import re

# ===========================
# Basic entity patterns
# ===========================

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_PATTERN = re.compile(r"\+?[0-9]{1,3}?[ -]?[0-9]{2,4}[ -]?[0-9]{2,4}[ -]?[0-9]{2,4}")
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
GOOGLE_ANALYTICS_PATTERN = re.compile(r"UA-\d{4,9}-\d{1,4}")
FACEBOOK_ANALYTICS_PATTERN = re.compile(r"fb\.\d+\.\d+\.\d+")

# ===========================
# Communication patterns
# ===========================

IRC_PATTERN = re.compile(r"irc://[a-zA-Z0-9.\-]+:\d+(?:/[a-zA-Z0-9\-_]+)?", re.IGNORECASE)
GPG_KEY_PATTERN = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)
SSH_KEY_PATTERN = re.compile(
    r"ssh-(rsa|ed25519|dsa|ecdsa)\s+[A-Za-z0-9+/=]+",
)
DISCORD_INVITE_PATTERN = re.compile(r"https?://(www\.)?discord\.gg/[a-zA-Z0-9]+")
WHATSAPP_INVITE_PATTERN = re.compile(r"https?://(www\.)?wa\.me/[0-9]+")
PAYPAL_LINK_PATTERN = re.compile(r"https?://(www\.)?paypal\.me/[a-zA-Z0-9._\-]+")

# ===========================
# Adult site patterns
# ===========================

ADULT_SITE_PATTERNS: dict[str, re.Pattern] = {
    "justforfans": re.compile(r"https?://(www\.)?justfor\.fans/[a-zA-Z0-9._\-]+"),
    "fancentro": re.compile(r"https?://(www\.)?fancentro\.com/[a-zA-Z0-9._\-]+"),
    "camsoda": re.compile(r"https?://(www\.)?camsoda\.com/[a-zA-Z0-9._\-]+"),
    "chaturbate": re.compile(r"https?://(www\.)?chaturbate\.com/[a-zA-Z0-9._\-]+"),
    "soulcams": re.compile(r"https?://(www\.)?soulcams\.com/[a-zA-Z0-9._\-]+"),
    "stripchat": re.compile(r"https?://(www\.)?stripchat\.com/[a-zA-Z0-9._\-]+"),
    "twitch": re.compile(r"https?://(www\.)?twitch\.tv/[a-zA-Z0-9._\-]+"),
    "fansly": re.compile(r"https?://(www\.)?fansly\.com/[a-zA-Z0-9._\-]+"),
}

# ===========================
# Social media patterns
# ===========================

SOCIAL_MEDIA_PATTERNS: dict[str, re.Pattern] = {
    "facebook": re.compile(r"https?://(www\.)?(facebook\.com|fb\.com)/[a-zA-Z0-9._\-]+"),
    "twitter": re.compile(r"https?://(www\.)?(twitter\.com|x\.com|t\.co)/[a-zA-Z0-9_]+"),
    "linkedin": re.compile(r"https?://(www\.)?linkedin\.com/(in|pub|company)/[a-zA-Z0-9\-_]+"),
    "instagram": re.compile(r"https?://(www\.)?instagram\.com/[a-zA-Z0-9._\-]+"),
    "youtube": re.compile(r"https?://(www\.)?(youtube\.com|youtu\.be)/(c|channel|user|watch\?v=)/[a-zA-Z0-9\-_]+"),
    "tiktok": re.compile(r"https?://(www\.)?tiktok\.com/@[a-zA-Z0-9._\-]+"),
    "snapchat": re.compile(r"https?://(www\.)?snapchat\.com/add/[a-zA-Z0-9._\-]+"),
    "pinterest": re.compile(r"https?://(www\.)?pinterest\.com/[a-zA-Z0-9._\-]+"),
    "reddit": re.compile(r"https?://(www\.)?reddit\.com/user/[a-zA-Z0-9\-_]+"),
    "github": re.compile(r"https?://(www\.)?github\.com/[a-zA-Z0-9._\-]+"),
    "telegram_user": re.compile(r"https?://(www\.)?t\.me/[a-zA-Z0-9._\-]+"),
    "telegram_invite": re.compile(r"https?://(www\.)?t\.me/joinchat/[a-zA-Z0-9\-_]+"),
    "telegram_group": re.compile(r"https?://(www\.)?t\.me/[\w]+/[\w]+"),
    "telegram_channel": re.compile(r"https?://(www\.)?t\.me/s/[\w]+"),
    "tumblr": re.compile(r"https?://(www\.)?[a-zA-Z0-9\-_]+\.tumblr\.com"),
    "medium": re.compile(r"https?://(www\.)?medium\.com/@[a-zA-Z0-9\-_]+"),
    "quora": re.compile(r"https?://(www\.)?quora\.com/profile/[a-zA-Z0-9\-_]+"),
    "vimeo": re.compile(r"https?://(www\.)?vimeo\.com/[a-zA-Z0-9\-_]+"),
    "dailymotion": re.compile(r"https?://(www\.)?dailymotion\.com/(video|user)/[a-zA-Z0-9\-_]+"),
    "flickr": re.compile(r"https?://(www\.)?flickr\.com/photos/[a-zA-Z0-9\-_]+"),
    "deviantart": re.compile(r"https?://(www\.)?deviantart\.com/[a-zA-Z0-9\-_]+"),
    "dribbble": re.compile(r"https?://(www\.)?dribbble\.com/[a-zA-Z0-9\-_]+"),
    "behance": re.compile(r"https?://(www\.)?behance\.net/[a-zA-Z0-9\-_]+"),
    "soundcloud": re.compile(r"https?://(www\.)?soundcloud\.com/[a-zA-Z0-9\-_]+"),
    "mixcloud": re.compile(r"https?://(www\.)?mixcloud\.com/[a-zA-Z0-9\-_]+"),
    "bandcamp": re.compile(r"https?://(www\.)?[a-zA-Z0-9\-_]+\.bandcamp\.com"),
    "spotify": re.compile(r"https?://(open\.)?spotify\.com/(user|artist|album|track)/[a-zA-Z0-9\-_]+"),
    "wechat": re.compile(r"https?://(www\.)?wechat\.com/[a-zA-Z0-9\-_]+"),
    "weibo": re.compile(r"https?://(www\.)?weibo\.com/[a-zA-Z0-9\-_]+"),
    "qq": re.compile(r"https?://(www\.)?qq\.com/[a-zA-Z0-9\-_]+"),
    "taringa": re.compile(r"https?://(www\.)?taringa\.net/[a-zA-Z0-9\-_]+"),
    "vk": re.compile(r"https?://(www\.)?vk\.com/[a-zA-Z0-9\-_]+"),
    "xing": re.compile(r"https?://(www\.)?xing\.com/profile/[a-zA-Z0-9\-_]+"),
    "minds": re.compile(r"https?://(www\.)?minds\.com/[a-zA-Z0-9\-_]+"),
    "bebo": re.compile(r"https?://(www\.)?bebo\.com/[a-zA-Z0-9\-_]+"),
    "ello": re.compile(r"https?://(www\.)?ello\.co/[a-zA-Z0-9\-_]+"),
    "plurk": re.compile(r"https?://(www\.)?plurk\.com/[a-zA-Z0-9\-_]+"),
    "myspace": re.compile(r"https?://(www\.)?myspace\.com/[a-zA-Z0-9\-_]+"),
}

# ===========================
# Cryptocurrency address patterns
# ===========================

CRYPTO_PATTERNS: dict[str, re.Pattern] = {
    "bitcoin": re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[q|p][a-zA-HJ-NP-Z0-9]{38,59})\b"),
    "bitcoin_cash": re.compile(r"\b((bitcoincash:)?[qQ][a-zA-Z0-9]{41}|(bitcoincash:)?[pP][a-zA-Z0-9]{41})\b"),
    "ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "litecoin": re.compile(r"\b([LM3][a-km-zA-HJ-NP-Z1-9]{26,33})\b"),
    "ripple": re.compile(r"\br[0-9a-zA-Z]{24,34}\b"),
    "dogecoin": re.compile(r"\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b"),
    "cardano": re.compile(r"\b(addr1|DdzFFzCqrh)[0-9a-zA-Z]{58,98}\b"),
    "polkadot": re.compile(r"\b1[a-km-zA-HJ-NP-Z1-9]{48}\b"),
    "stellar": re.compile(r"\bG[a-zA-Z0-9]{56}\b"),
    "monero": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "dash": re.compile(r"\b(X|7)[a-zA-Z0-9]{33}\b"),
    "zcash": re.compile(r"\b(t1|t3|z)[a-zA-Z0-9]{34,42}\b"),
    "tron": re.compile(r"\bT[a-zA-Z0-9]{33}\b"),
    "vechain": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "neo": re.compile(r"\bA[a-zA-Z0-9]{33}\b"),
    "binance_coin": re.compile(r"\b(bnb1)[a-z0-9]{38}\b"),
    "eos": re.compile(r"\b[1-5a-z]{12}\b"),
    "tezos": re.compile(r"\b(tz1|tz2|tz3|KT1)[1-9A-HJ-NP-Za-km-z]{33}\b"),
    "iota": re.compile(r"\b[a-zA-Z9]{81}\b"),
    "nem": re.compile(r"\b(NC|NA|NB|ND)[0-9A-HJ-NP-Za-km-z]{39}\b"),
    "solana": re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{44}\b"),
    "avalanche": re.compile(r"\b(X-|C-)[a-zA-HJ-NP-Z0-9]{33,34}\b"),
    "algorand": re.compile(r"\b[a-zA-Z0-9]{58}\b"),
    "harmony": re.compile(r"\b(one1)[0-9a-z]{38}\b"),
    "elrond": re.compile(r"\b(erd1)[0-9a-z]{38}\b"),
    "cosmos": re.compile(r"\b(cosmos1)[0-9a-z]{38}\b"),
    "hedera": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "ontology": re.compile(r"\b(AO)[a-zA-Z0-9]{33}\b"),
    "qtum": re.compile(r"\b(Q|M)[a-zA-Z0-9]{33}\b"),
    "waves": re.compile(r"\b(3P)[a-zA-HJ-NP-Z0-9]{33}\b"),
}

# Map crypto pattern names to DataModel field names
CRYPTO_FIELD_MAP: dict[str, str] = {
    "bitcoin": "bitcoin_address",
    "ethereum": "ethereum_address",
    "monero": "monero_address",
    "litecoin": "litecoin_address",
    "zcash": "zcash_address",
}

# ===========================
# Code language detection patterns
# ===========================

CODE_PATTERNS: dict[str, re.Pattern] = {
    "python": re.compile(r"(?:def|class|import|from)\s+[a-zA-Z_][a-zA-Z0-9_]*|\"\"\"[^\"]*\"\"\"|'''[^']*'''|#[^\"\']*$"),
    "javascript": re.compile(r"function\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(|const\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*|//[^\"\']*$"),
    "java": re.compile(r"(?:public|protected|private|static|final|void|int|String|class)\s+[a-zA-Z_][a-zA-Z0-9_]*|/\*[^*]*\*/|//[^\"\']*$"),
    "html": re.compile(r"<[a-zA-Z][a-zA-Z0-9]*[^>]*>|<!--[^-]*-->"),
    "sql": re.compile(r"SELECT\s+[a-zA-Z_][a-zA-Z0-9_]*|INSERT\s+INTO\s+[a-zA-Z_][a-zA-Z0-9_]*|UPDATE\s+[a-zA-Z_][a-zA-Z0-9_]*\s+SET|DELETE\s+FROM\s+[a-zA-Z_][a-zA-Z0-9_]*", re.IGNORECASE),
    "c": re.compile(r"#include\s+<[a-zA-Z0-9_.]+>|int\s+main\s*\(|/\*[^*]*\*/|//[^\"\']*$"),
    "cpp": re.compile(r"#include\s+<[a-zA-Z0-9_.]+>|std::[a-zA-Z_][a-zA-Z0-9_]*|class\s+[a-zA-Z_][a-zA-Z0-9_]*|/\*[^*]*\*/|//[^\"\']*$"),
    "csharp": re.compile(r"using\s+[a-zA-Z_][a-zA-Z0-9_.]*;|public\s+class\s+[a-zA-Z_][a-zA-Z0-9_]*|/\*[^*]*\*/|//[^\"\']*$"),
    "php": re.compile(r"<\?php|\$[a-zA-Z_][a-zA-Z0-9_]*|echo\s+[a-zA-Z_][a-zA-Z0-9_]*|//[^\"\']*$"),
    "ruby": re.compile(r"def\s+[a-zA-Z_][a-zA-Z0-9_]*|class\s+[a-zA-Z_][a-zA-Z0-9_]*|#[^\"\']*$"),
    "perl": re.compile(r"use\s+[a-zA-Z_][a-zA-Z0-9_]*;|\$[a-zA-Z_][a-zA-Z0-9_]*|#[^\"\']*$"),
    "r": re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*\s*<-\s*|#[^\"\']*$"),
    "go": re.compile(r"package\s+[a-zA-Z_][a-zA-Z0-9_]*|func\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(|import\s+\"[a-zA-Z_][a-zA-Z0-9_]*\""),
    "swift": re.compile(r"import\s+[a-zA-Z_][a-zA-Z0-9_]*|class\s+[a-zA-Z_][a-zA-Z0-9_]*|func\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\("),
    "delphi": re.compile(r"program\s+[a-zA-Z_][a-zA-Z0-9_]*;|begin\s+[^end]*end\.|var\s+[a-zA-Z_][a-zA-Z0-9_]*"),
    "scala": re.compile(r"object\s+[a-zA-Z_][a-zA-Z0-9_]*|def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(|//[^\"\']*$"),
    "kotlin": re.compile(r"fun\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(|val\s+[a-zA-Z_][a-zA-Z0-9_]*|//[^\"\']*$"),
    "typescript": re.compile(r"const\s+[a-zA-Z_][a-zA-Z0-9_]*:\s+[a-zA-Z_][a-zA-Z0-9_]*|function\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(|//[^\"\']*$"),
    "lua": re.compile(r"local\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=|function\s+[a-zA-Z_][a-zA-Z0-9_]*|--[^\"\']*$"),
    "matlab": re.compile(r"function\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[a-zA-Z_][a-zA-Z0-9_]*\(|%[^\"\']*$"),
    "haskell": re.compile(r"module\s+[a-zA-Z_][a-zA-Z0-9_]*|import\s+[a-zA-Z_][a-zA-Z0-9_]*|--[^\"\']*$"),
    "clojure": re.compile(r"\([a-zA-Z_][a-zA-Z0-9_]*\s+[a-zA-Z_][a-zA-Z0-9_]*|;[^\"\']*$"),
    "groovy": re.compile(r"def\s+[a-zA-Z_][a-zA-Z0-9_]*|class\s+[a-zA-Z_][a-zA-Z0-9_]*|//[^\"\']*$"),
    "shell": re.compile(r"#!/bin/bash|#[^\"\']*$|echo\s+\"[a-zA-Z_][a-zA-Z0-9_]*\""),
}

# ===========================
# IOC (Indicator of Compromise) patterns
# ===========================

# File hash patterns
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA512_PATTERN = re.compile(r"\b[a-fA-F0-9]{128}\b")

# CVE pattern
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Domain pattern (excludes common false positives like file extensions)
DOMAIN_PATTERN = re.compile(
    r"\b(?:(?!www\.|http)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

# URL pattern (comprehensive, for plain text)
URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+")

# Defanged IOC patterns
DEFANGED_IP_PATTERN = re.compile(
    r"\b\d{1,3}[\[\(]?\.\]\)]?\d{1,3}[\[\(]?\.\]\)]?\d{1,3}[\[\(]?\.\]\)]?\d{1,3}\b"
)
DEFANGED_DOMAIN_PATTERN = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]*\[\.\][a-zA-Z0-9-]+)+\b"
)
DEFANGED_EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+-]+[\[\(]?\@[\]\)]?[a-zA-Z0-9.-]+[\[\(]?\.\]\)]?[a-zA-Z]{2,}"
)

# YARA rule pattern
YARA_RULE_PATTERN = re.compile(
    r"rule\s+\w+[\s\S]*?\{[\s\S]*?condition:\s*[\s\S]*?\}",
    re.IGNORECASE,
)

# Sigma rule pattern (YAML-based, detection block)
SIGMA_RULE_PATTERN = re.compile(
    r"(?ms)^title:\s.*?^(?:(?!^title:).)*?detection:\s.*?condition:.*?(?=\n[a-zA-Z]|\Z)",
)

# MITRE ATT&CK technique ID pattern
MITRE_TECHNIQUE_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
MITRE_TACTIC_PATTERN = re.compile(r"\bTA\d{4}\b")

# CPE (Common Platform Enumeration) pattern
CPE_PATTERN = re.compile(r"cpe:[23]:/[a-zA-Z0-9._\-~%]+(:[a-zA-Z0-9._\-~%]+)*")

# MAC address pattern
MAC_PATTERN = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

# IPv6 pattern (simplified)
IPV6_PATTERN = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b")

# User-Agent pattern
USER_AGENT_PATTERN = re.compile(
    r"[a-zA-Z0-9._\-]+/[a-zA-Z0-9.]+(\s*\([a-zA-Z0-9._\-;\s]+\))*"
)

# JARM fingerprint pattern (62 hex chars)
JARM_PATTERN = re.compile(r"\b[a-fA-F0-9]{62}\b")

# ASN pattern
ASN_PATTERN = re.compile(r"\bAS\d{1,10}\b", re.IGNORECASE)

# CIDR notation pattern
CIDR_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b")

# Convenience dict mapping IOC type names to compiled patterns
IOC_PATTERNS: dict[str, re.Pattern] = {
    "md5": MD5_PATTERN,
    "sha1": SHA1_PATTERN,
    "sha256": SHA256_PATTERN,
    "sha512": SHA512_PATTERN,
    "cve": CVE_PATTERN,
    "domain": DOMAIN_PATTERN,
    "url": URL_PATTERN,
    "ipv4": IP_PATTERN,
    "ipv6": IPV6_PATTERN,
    "mac": MAC_PATTERN,
    "cidr": CIDR_PATTERN,
    "asn": ASN_PATTERN,
    "cpe": CPE_PATTERN,
    "jarm": JARM_PATTERN,
    "mitre_technique": MITRE_TECHNIQUE_PATTERN,
    "mitre_tactic": MITRE_TACTIC_PATTERN,
    "yara_rule": YARA_RULE_PATTERN,
    "sigma_rule": SIGMA_RULE_PATTERN,
    "user_agent": USER_AGENT_PATTERN,
}
