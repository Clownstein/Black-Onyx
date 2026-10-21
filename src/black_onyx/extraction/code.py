"""Code snippet detection using Pygments with regex fallback."""

from __future__ import annotations

import logging

from black_onyx.extraction.patterns import CODE_PATTERNS

logger = logging.getLogger(__name__)


def detect_code_snippets(text: str) -> tuple[list[str], list[str]]:
    """Detect code snippets and their languages in the given text.

    Uses Pygments' guess_lexer() for primary detection, falling back to
    regex patterns from patterns.py if Pygments cannot identify the language.

    Args:
        text: The text to analyze.

    Returns:
        Tuple of (code_snippets, code_languages). code_snippets contains the
        detected code text, code_languages contains the corresponding language names.
    """
    code_snippets: list[str] = []
    code_languages: list[str] = []

    # Try Pygments first
    try:
        from pygments.lexers import guess_lexer
        from pygments.util import ClassNotFound

        lexer = guess_lexer(text)
        if lexer:
            code_snippets.append(text[:5000])  # Truncate very long text
            code_languages.append(lexer.name)
            return code_snippets, code_languages
    except ClassNotFound:
        logger.debug("Pygments could not identify code language, falling back to regex")
    except Exception as e:
        logger.debug(f"Pygments guess_lexer failed: {e}, falling back to regex")

    # Fallback: regex-based detection
    for lang, pattern in CODE_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            # If we find multiple language indicators, record the text once per language
            # but only if it's a strong match (more than 2 matches)
            if len(matches) > 2:
                code_snippets.append(text[:5000])
                code_languages.append(lang)
                break  # Take the first strong match

    return code_snippets, code_languages
