"""Intelligence report generation — LLM-powered summaries with multiple export formats."""

from __future__ import annotations

from datetime import datetime
import html
from typing import Any


class ReportGenerator:
    """Generate intelligence reports from Qdrant search results, IOCs, and enrichment data.

    Uses the LLM provider to generate narrative summaries, then exports
    in Markdown, HTML, or PDF format.
    """

    def __init__(self, llm_provider: Any = None) -> None:
        self._llm = llm_provider

    def generate_markdown_report(
        self,
        title: str,
        iocs: dict[str, list],
        enrichments: list[dict] | None = None,
        mitre_techniques: list[dict] | None = None,
        search_results: list[dict] | None = None,
        case_id: str | None = None,
    ) -> str:
        """Generate a Markdown intelligence report."""
        sections: list[str] = []
        safe_title = title.replace("\r", " ").replace("\n", " ").strip()
        sections.append(f"# {safe_title}\n")
        sections.append(f"**Generated:** {datetime.now().isoformat()}\n")
        if case_id:
            sections.append(f"**Case ID:** {case_id}\n")

        # Executive Summary
        if self._llm:
            try:
                summary = self._generate_executive_summary(iocs, enrichments, mitre_techniques)
                sections.append(f"## Executive Summary\n\n{summary}\n")
            except Exception:
                sections.append("## Executive Summary\n\n*LLM summary generation failed.*\n")
        else:
            sections.append("## Executive Summary\n\n*LLM not configured — skipping narrative summary.*\n")

        # IOC Table
        sections.append("## Indicators of Compromise\n")
        sections.append("| Type | Value |")
        sections.append("|------|-------|")
        for ioc_type, values in iocs.items():
            if isinstance(values, list):
                for v in values:
                    safe_type = str(ioc_type).replace("|", "\\|")
                    safe_value = str(v).replace("`", "\\`").replace("|", "\\|")
                    sections.append(f"| {safe_type} | `{safe_value}` |")
        sections.append("")

        # Enrichment Results
        if enrichments:
            sections.append("## Enrichment Results\n")
            for enr in enrichments:
                sections.append(f"### {enr.get('provider', 'Unknown')} — {enr.get('ioc_value', 'N/A')}")
                sections.append(f"- **Malicious:** {enr.get('malicious', 'Unknown')}")
                sections.append(f"- **Confidence:** {enr.get('confidence', 'N/A')}")
                if enr.get("tags"):
                    sections.append(f"- **Tags:** {', '.join(enr['tags'])}")
                if enr.get("error"):
                    sections.append(f"- **Error:** {enr['error']}")
                sections.append("")

        # MITRE ATT&CK
        if mitre_techniques:
            sections.append("## MITRE ATT&CK Mapping\n")
            for tech in mitre_techniques:
                tid = tech.get("technique_id", "")
                name = tech.get("name", "Unknown")
                tactics = tech.get("tactic", [])
                sections.append(f"- **{tid}** — {name} ({', '.join(tactics) if tactics else 'N/A'})")
            sections.append("")

        # Recommendations
        sections.append("## Recommendations\n")
        sections.append("1. Block identified malicious IPs and domains at the firewall/proxy.")
        sections.append("2. Search SIEM for identified file hashes.")
        sections.append("3. Apply patches for referenced CVEs.")
        sections.append("4. Implement Sigma rules generated from these IOCs.")
        sections.append("5. Review and escalate any confirmed malicious indicators.")
        sections.append("")

        # Appendix — Search Results
        if search_results:
            sections.append("## Appendix — Source Data\n")
            for i, result in enumerate(search_results[:10]):
                score = result.get("score", 0)
                source = result.get("payload", {}).get("source_file", "unknown")
                sections.append(f"### Result {i+1} (score: {score:.3f})\n")
                sections.append(f"**Source:** `{source}`\n")
                body = result.get("payload", {}).get("body_text", "")
                if body:
                    sections.append(f"```\n{body[:500]}...\n```\n")

        return "\n".join(sections)

    def markdown_to_html(self, markdown: str) -> str:
        """Convert Markdown report to styled HTML."""
        try:
            import markdown as md  # type: ignore[import-untyped]
            html_body = md.markdown(markdown, extensions=["tables", "fenced_code"])
        except ImportError:
            # Minimal fallback
            html_body = html.escape(markdown).replace("\n", "<br>\n")
        import bleach  # type: ignore[import-untyped]
        html_body = bleach.clean(
            html_body,
            tags={"h1", "h2", "h3", "p", "strong", "em", "ul", "ol", "li",
                  "table", "thead", "tbody", "tr", "th", "td", "pre", "code", "br"},
            attributes={},
            protocols=set(),
            strip=True,
        )
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Intelligence Report</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #f4f4f4; }}
code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
h1 {{ color: #333; border-bottom: 2px solid #333; }}
h2 {{ color: #444; border-bottom: 1px solid #ccc; }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

    def generate_pdf(self, markdown: str, output_path: str) -> bool:
        """Convert Markdown report to PDF. Returns True on success."""
        try:
            from weasyprint import HTML
            html_content = self.markdown_to_html(markdown)
            HTML(string=html_content).write_pdf(output_path)
            return True
        except ImportError:
            try:
                import pdfkit
                html_content = self.markdown_to_html(markdown)
                pdfkit.from_string(html_content, output_path)
                return True
            except ImportError:
                return False

    def _generate_executive_summary(
        self,
        iocs: dict[str, list],
        enrichments: list[dict] | None,
        techniques: list[dict] | None,
    ) -> str:
        """Use LLM to generate a narrative executive summary."""
        from black_onyx.llm.base import ChatMessage

        # Build context
        ioc_summary = []
        for ioc_type, values in iocs.items():
            if isinstance(values, list) and values:
                ioc_summary.append(f"- {ioc_type}: {len(values)} found")
        ioc_text = "\n".join(ioc_summary) or "No IOCs found."

        enrichment_text = ""
        if enrichments:
            malicious_count = sum(1 for e in enrichments if e.get("malicious"))
            enrichment_text = f"\nEnrichment: {len(enrichments)} results, {malicious_count} confirmed malicious."

        technique_text = ""
        if techniques:
            technique_text = f"\nMITRE ATT&CK: {len(techniques)} techniques identified."

        prompt = (
            f"You are a cybersecurity threat intelligence analyst. "
            f"Write a concise executive summary (2-3 paragraphs) of the following threat intelligence findings:\n\n"
            f"IOCs found:\n{ioc_text}\n{enrichment_text}\n{technique_text}\n\n"
            f"Summarize the threat, its potential impact, and recommended actions."
        )

        messages = [ChatMessage(role="user", content=prompt)]
        response = self._llm.chat(messages, system_prompt="You are a cybersecurity analyst.", max_tokens=512)
        return response.text
