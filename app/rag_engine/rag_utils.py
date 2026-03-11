# backend/app/rag_engine/rag_utils.py
import re
import json
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import google.generativeai as genai
from openai import OpenAI

from app.config import settings
from app.schemas.rag_schema import RAGExplanationResponse, MITRETechnique
from app.rag_engine.mitre_db import find_mitre_techniques

logger = logging.getLogger("app.rag_engine.rag_utils")
logger.setLevel(logging.INFO)

# Models
GEMINI_MODEL = "gemini-2.5-flash-lite"
OPENAI_MODEL = "gpt-4o-mini"

# -----------------------------------------------------------------------------
# GitHub configuration (from .env)
# -----------------------------------------------------------------------------
GITHUB_API_BASE = "https://api.github.com"
GITHUB_TOKEN = settings.GITHUB_TOKEN

logger.info(f"[RAG] GitHub token loaded: {bool(GITHUB_TOKEN)}")

# -----------------------------------------------------------------------------
# CVE detection
# -----------------------------------------------------------------------------
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_cve_ids(text: str) -> List[str]:
    if not text:
        return []
    return list(set(CVE_REGEX.findall(text.upper())))


# -----------------------------------------------------------------------------
# Severity enum and helpers
# -----------------------------------------------------------------------------
class SeverityLevel(Enum):
    CRITICAL = (90, 100, "🔴")
    HIGH = (70, 89, "🟠")
    MEDIUM = (40, 69, "🟡")
    LOW = (20, 39, "🟢")
    INFO = (0, 19, "🔵")


def severity_label(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def severity_color(score: int) -> str:
    if score >= 90:
        return "#dc2626"  # red
    if score >= 70:
        return "#ea580c"  # orange
    if score >= 40:
        return "#f59e0b"  # yellow
    if score >= 20:
        return "#16a34a"  # green
    return "#2563eb"      # blue


# -----------------------------------------------------------------------------
# GitHub helpers (optional enrichment)
# -----------------------------------------------------------------------------
def _github_headers() -> Dict[str, str]:
    if not GITHUB_TOKEN:
        raise RuntimeError("GITHUB_TOKEN not configured")
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def fetch_github_advisories(keyword: str, limit: int = 3) -> List[str]:
    """
    Fetch GitHub Security Advisories related to the threat.
    Safe fallback if GitHub API fails.
    """
    if not GITHUB_TOKEN:
        return []

    try:
        resp = requests.get(
            f"{GITHUB_API_BASE}/search/advisories",
            headers=_github_headers(),
            params={"q": keyword, "per_page": limit},
            timeout=5
        )
        resp.raise_for_status()
        data = resp.json()

        return [
            f"{item.get('ghsa_id')} – {item.get('summary')}"
            for item in data.get("items", [])
        ]

    except Exception as e:
        logger.warning(f"[RAG] GitHub advisory fetch failed: {e}")
        return []

# -----------------------------------------------------------------------------
# Theme configuration (icons/colors/keywords)
# -----------------------------------------------------------------------------
class ExplanationTheme:
    THEMES = {
        "malware": {"icon": "🦠", "color": "#dc2626", "keywords": ["malware", "trojan", "virus", "ransom"]},
        "phishing": {"icon": "🎣", "color": "#ea580c", "keywords": ["phishing", "email", "credential", "spoof"]},
        "network": {"icon": "🌐", "color": "#2563eb", "keywords": ["port", "scan", "ddos", "dos", "protocol"]},
        "default": {"icon": "⚠️", "color": "#6b7280", "keywords": []},
    }

    @classmethod
    def get_theme(cls, threat_type: str) -> Dict[str, Any]:
        t = (threat_type or "").lower()
        for key, theme in cls.THEMES.items():
            if key in t:
                return theme
        return cls.THEMES["default"]


# -----------------------------------------------------------------------------
# RAG Utility (Level 3: HTML + colors + icons)
# -----------------------------------------------------------------------------
class RAGUtility:
    def __init__(self):
        self.gemini_ready = False
        self.openai_ready = False
        self.explanation_cache: Dict[str, RAGExplanationResponse] = {}
        self.init_error = None

        # Init Gemini
        try:
            if settings.GOOGLE_API_KEY:
                genai.configure(api_key=settings.GOOGLE_API_KEY)
                self.gemini_ready = True
                logger.info("[RAG] Gemini initialized")
        except Exception as e:
            logger.error(f"[RAG] Gemini init failed: {e}")
            self.init_error = str(e)

        # Init OpenAI
        try:
            if settings.OPENAI_API_KEY:
                self.openai_client = OpenAI(api_key=settings.OPENAI_API_KEY)
                self.openai_ready = True
                logger.info("[RAG] OpenAI initialized")
        except Exception as e:
            logger.error(f"[RAG] OpenAI init failed: {e}")
            self.init_error = str(e)

    # -------------------------
    # LLM calls (unchanged)
    # -------------------------
    def _call_gemini(self, prompt: str) -> Optional[str]:
        if not self.gemini_ready:
            return None
        try:
            model = genai.GenerativeModel(GEMINI_MODEL)
            result = model.generate_content(prompt)
            return result.text
        except Exception as e:
            logger.error(f"[RAG] Gemini error: {e}")
            self.init_error = f"Gemini: {e}"
            return None

    def _call_openai(self, prompt: str) -> Optional[str]:
        if not self.openai_ready:
            return None
        try:
            res = self.openai_client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "Return strictly JSON with the requested fields."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
            )
            return res.choices[0].message.content
        except Exception as e:
            logger.error(f"[RAG] OpenAI error: {e}")
            self.init_error = f"OpenAI: {e}"
            return None

    # -------------------------
    # Public entry
    # -------------------------
    def generate_explanation(self, threat_type: str, context_data: Dict[str, Any]) -> RAGExplanationResponse:
        cache_key = f"{threat_type}_{hash(str(context_data))}"
        if cache_key in self.explanation_cache:
            return self.explanation_cache[cache_key]

        prompt = self._build_prompt(threat_type, context_data)

        # Try Gemini
        out = self._call_gemini(prompt)
        if out:
            try:
                resp = self._process_and_build(threat_type, context_data, out)
                self.explanation_cache[cache_key] = resp
                return resp
            except Exception as e:
                logger.warning(f"[RAG] Gemini output parse/process error: {e}")

        # Try OpenAI fallback
        out = self._call_openai(prompt)
        if out:
            try:
                resp = self._process_and_build(threat_type, context_data, out)
                self.explanation_cache[cache_key] = resp
                return resp
            except Exception as e:
                logger.warning(f"[RAG] OpenAI output parse/process error: {e}")

        # Final fallback
        resp = self._final_fallback(threat_type, context_data)
        self.explanation_cache[cache_key] = resp
        return resp
    

            # -------------------------
    # Prompt (guidelines) – User friendly
    # -------------------------
    def _build_prompt(self, threat_type: str, data: Dict[str, Any]) -> str:
        ctx = json.dumps(data, indent=2)

        return f"""
    You are a senior SOC analyst writing for NORMAL, NON-TECHNICAL users.

    Analyze this {threat_type} scan result and return ONLY a JSON object with these keys:
    short_summary, summary, full_explanation, severity, mitre_techniques.

    IMPORTANT STYLE RULES:
    - Use very simple English.
    - Explain like you are talking to a normal user, not a security expert.
    - NO markdown, NO code blocks, NO asterisks.
    - Use ONLY single bullet points using the symbol "•".
    - Each bullet point must be ONE clear sentence.
    - Do NOT return arrays or nested objects inside full_explanation.
    - Do NOT repeat the same point in multiple sections.

    full_explanation MUST contain the following sections EXACTLY in this order:

    Threat Overview:
    • What the threat is
    • Why it appeared in this scan

    Immediate Impact:
    • What can happen right now
    • Who or what is affected

    Attack Chain:
    • How the attack usually starts
    • What it tries to do next

    Evidence Summary:
    • Write ONLY clean, point-wise evidence
    • One bullet per finding
    • If VirusTotal data exists, write like:
    • X security engines marked this as malicious
    • X engines marked this as suspicious
    • X engines marked this as safe
    • Do NOT include raw arrays, engine lists, or JSON

    How Dangerous It Is:
    • Overall risk level explained in simple words

    How To Stay Safe:
    • What a normal user should immediately do

    How To Avoid This Threat:
    • How to prevent this in the future

    Recommended Actions:
    • Clear actions for users or admins
    • Keep actions practical and simple

    If information for a section is not available, write:
    • No information available.

    Context (do NOT repeat this directly in output):
    {ctx}
    """

    

        # -------------------------
    # CVE-specific prompt (DEFENSIVE ONLY)
    # -------------------------
    def _build_cve_prompt(self, cve_id: str, data: Dict[str, Any]) -> str:
        ctx = json.dumps(data, indent=2)

        return f"""
You are a senior security engineer.

Analyze vulnerability {cve_id}. This is a DEFENSIVE request.

STRICT RULES:
- DO NOT provide exploit code or payloads
- DO NOT provide offensive commands
- ONLY provide remediation, patching, and hardening steps

Return ONLY a JSON object with keys:
short_summary, summary, full_explanation, severity, mitre_techniques.

full_explanation MUST include these sections using bullet points (•):

Vulnerability Overview:
Affected Software:
Root Cause:
Impact:
How Attackers Abuse This:
Safe Remediation Steps:
Patch / Update Commands (SAFE ADMIN COMMANDS ONLY):
Temporary Mitigations:
Verification Steps:

If exact patch commands are unknown, say "Consult vendor advisory".

Context:
{ctx}
"""

    # -------------------------
    # Parse and build both plain and HTML output
    # -------------------------
    def _process_and_build(self, threat_type: str, ctx: Dict[str, Any], raw_text: str) -> RAGExplanationResponse:
        short, summ, full_raw, sev, mitres = self._parse_raw(raw_text)

        # Build structured plain text
        plain_text = self._build_structured_plain(full_raw, ctx, sev)

        # Build HTML version
        theme = ExplanationTheme.get_theme(threat_type)
        html = self._build_html_from_structured(plain_text, threat_type, theme, sev, ctx)

        # Ensure MITRE fallback
        if not mitres:
            mitres = [
                MITRETechnique(id=m["id"], name=m["name"])
                for m in find_mitre_techniques(str(ctx))
            ]

        response = RAGExplanationResponse(
            explanation_id=None,
            generated_at=datetime.utcnow(),
            short_summary=f"{theme['icon']} {short}",
            summary=summ or short,
            full_explanation=plain_text,
            severity=sev,
            mitre_techniques=mitres[:8],
            # Many of your frontends accept extra fields; include html and theme info.
            # If your Pydantic schema is strict, add these fields to the schema.
            theme_icon=theme["icon"],
            theme_color=theme["color"],
        )

        # attach html in a safe place: add attribute if possible
        try:
            # Try to set attribute on Pydantic object (works if model allows)
            setattr(response, "full_explanation_html", html)
        except Exception:
            # If Pydantic is strict and rejects additional attributes, it's okay;
            # frontend can render 'full_explanation' instead by converting plain text to HTML.
            pass

        return response

    # -------------------------
    # Raw parser: try JSON then fallback to plain
    # -------------------------
    def _parse_raw(self, raw_text: str) -> Tuple[str, str, Any, int, List[MITRETechnique]]:
        # Defaults
        short = "Threat detected"
        summ = ""
        full = ""
        sev = 50
        mitres: List[MITRETechnique] = []

        # Try to extract first JSON block
        try:
            m = re.search(r"(\{[\s\S]*\})", raw_text)
            if m:
                parsed = json.loads(m.group(1))
                short = str(parsed.get("short_summary", short))
                summ = str(parsed.get("summary", summ))
                full = parsed.get("full_explanation", "")
                sev_raw = parsed.get("severity", sev)
                try:
                    sev = int(sev_raw)
                except:
                    sev = sev
                # parse mitre
                mitre_raw = parsed.get("mitre_techniques", [])
                mitres = [
                    MITRETechnique(id=str(x.get("id", "")).strip(), name=str(x.get("name", "")).strip())
                    for x in mitre_raw if isinstance(x, dict) and x.get("id") and x.get("name")
                ]
                return short, summ, full, sev, mitres
        except Exception:
            logger.debug("[RAG] JSON parse failed; treat raw_text as plain string")

        # fallback regex extraction for labelled fields
        # short_summary
        try:
            m = re.search(r'"short_summary"\s*:\s*"([^"]+)"', raw_text)
            if m:
                short = m.group(1).strip()
        except:
            pass

        # summary
        try:
            m = re.search(r'"summary"\s*:\s*"([^"]+)"', raw_text)
            if m:
                summ = m.group(1).strip()
        except:
            pass

        # severity
        try:
            m = re.search(r'"severity"\s*:\s*(\d+)', raw_text)
            if m:
                sev = int(m.group(1))
        except:
            pass

        # if no structured full, set to whole raw_text
        full = raw_text if not full else full
        return short, summ, full, sev, mitres

    # -------------------------
    # Build plain structured text from raw full (handles dicts and strings)
    # -------------------------
    def _build_structured_plain(self, full_raw: Any, ctx: Dict[str, Any], severity: int) -> str:
        # If the model already returned a dict-like object (or JSON string with dict)
        if isinstance(full_raw, dict):
            data = full_raw
        else:
            # try parse if full_raw contains JSON-like dict
            try:
                if isinstance(full_raw, str):
                    # attempt to parse JSON if it's a dict-looking string
                    block = re.search(r"(\{[\s\S]*\})", full_raw)
                    if block:
                        data = json.loads(block.group(1))
                    else:
                        data = self._parse_plain_sections(full_raw)
                else:
                    data = self._parse_plain_sections(str(full_raw))
            except Exception:
                data = self._parse_plain_sections(str(full_raw))

        # canonical list of sections we expect
        sections = [
            "Threat Overview",
            "Immediate Impact",
            "Attack Chain",
            "Evidence Summary",
            "How Dangerous It Is",
            "How To Stay Safe",
            "How To Avoid This Threat",
            "Recommended Actions"
        ]

        lines: List[str] = []

        for sec in sections:
            lines.append(f"{sec}:")
            value = data.get(sec)
            if value is None:
                # attempt to find case-insensitive key
                for k in data.keys():
                    if k.lower().strip() == sec.lower().strip():
                        value = data[k]
                        break

            if isinstance(value, list):
                for it in value:
                    lines.append(f"• {self._clean_text(it)}")
            elif isinstance(value, str) and value.strip():
                # If string contains multiple lines, break into bullets when appropriate.
                bullets = [s.strip() for s in re.split(r"\n{1,2}", value) if s.strip()]
                for b in bullets:
                    lines.append(f"• {self._clean_text(b)}")
            else:
                lines.append("• No information available.")
            lines.append("")  # spacing

        # Add automatic Evidence Summary details from context (if available)
        vt = ctx.get("vt_details") if isinstance(ctx, dict) else None
        if vt:
            # Insert at Evidence Summary (replace "No information available." if present)
            es_index = None
            for i, ln in enumerate(lines):
                if ln.startswith("Evidence Summary:"):
                    es_index = i
                    break
            if es_index is not None:
                extras = []
                mc = vt.get("malicious_count") or vt.get("malicious", None)
                sc = vt.get("suspicious_count") or vt.get("suspicious", None)
                hc = vt.get("harmless_count") or vt.get("harmless", None)
                total = vt.get("total", vt.get("total_engines", None))
                if mc:
                    extras.append(f"• Malicious detections: {mc}")
                if sc:
                    extras.append(f"• Suspicious detections: {sc}")
                if hc:
                    extras.append(f"• Harmless engines: {hc}")
                if total:
                    extras.append(f"• Total engines: {total}")
                # inject extras after Evidence Summary header
                insert_pos = es_index + 1
                # if current next line is "• No information available." remove it
                if insert_pos < len(lines) and lines[insert_pos].startswith("• No information"):
                    lines.pop(insert_pos)
                for ex in extras:
                    lines.insert(insert_pos, ex)
                    insert_pos += 1
                lines.insert(insert_pos, "")  # spacing

        # Append severity at the end
        lines.append(self._severity_line(severity))
        return "\n".join(lines).strip()

    # -------------------------
    # Attempt to parse plain text into sections (very forgiving)
    # returns dict(section -> content)
    # -------------------------
    def _parse_plain_sections(self, text: str) -> Dict[str, Any]:
        # Split by known section labels (case-insensitive)
        sections = {}
        labels = [
            "Threat Overview", "Immediate Impact", "Attack Chain", "Evidence Summary",
            "How Dangerous It Is", "How To Stay Safe", "How To Avoid This Threat", "Recommended Actions"
        ]
        # Normalize line endings
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        # Build regex to split at "Label:" lines
        # Add fallback: if no label present, put entire text under Threat Overview
        found_any = False
        current_label = "Threat Overview"
        buffer: List[str] = []

        for line in text.split("\n"):
            s = line.strip()
            if not s:
                continue
            # match label with trailing colon
            m = re.match(r"^([A-Za-z \-]{3,60}):\s*$", s)
            if m:
                # store previous
                if buffer:
                    sections.setdefault(current_label, []).append("\n".join(buffer).strip())
                buffer = []
                label = m.group(1).strip()
                current_label = label
                found_any = True
                continue
            # If the line starts with bullet indicator like • or - , keep as bullet content
            buffer.append(s)

        if buffer:
            sections.setdefault(current_label, []).append("\n".join(buffer).strip())

        if not found_any:
            # put everything into Threat Overview as lines
            sections = {"Threat Overview": [text.strip()]}

        # Normalize values: lists -> keep as list of bullets
        normalized = {}
        for k, v in sections.items():
            combined = []
            for item in v:
                # split multi-line into separate bullets
                parts = [p.strip() for p in re.split(r"\n{1,2}", item) if p.strip()]
                combined.extend(parts)
            normalized[k] = combined
        return normalized

    # -------------------------
    # Build an HTML card from plain structured explanation
    # -------------------------
    def _build_html_from_structured(self, plain_text: str, threat_type: str, theme: Dict[str, Any], severity: int, ctx: Dict[str, Any]) -> str:
        # Convert plain_text into sections dictionary
        parts = [p for p in re.split(r"\n\s*\n", plain_text) if p.strip()]
        sections = []
        current_title = None
        current_items = []
        for part in parts:
            lines = [l.strip() for l in part.split("\n") if l.strip()]
            if not lines:
                continue
            # first line is title if ends with ":" else treat as title guess
            if lines[0].endswith(":"):
                title = lines[0].rstrip(":")
                items = [ln.lstrip("• ").strip() for ln in lines[1:]]
                sections.append((title, items))
            else:
                # fallback: group under Threat Overview if no explicit title
                sections.append(("Threat Overview", [ln.lstrip("• ").strip() for ln in lines]))
        # Inline CSS for the card (minimal, self-contained)
        sev_label = severity_label(severity)
        sev_color = severity_color(severity)
        theme_icon = theme.get("icon", "⚠️")
        theme_color = theme.get("color", "#6b7280")
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        # Build HTML
        html_parts = []
        html_parts.append(f"""<div style="font-family: Inter, Arial, sans-serif; color:#E6EEF3; background:#0f1724; padding:18px; border-radius:10px; line-height:1.45;">""")
        # Header
        html_parts.append(f"""
  <div style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
    <div style="display:flex; align-items:center; gap:12px;">
      <div style="font-size:26px;">{theme_icon}</div>
      <div>
        <div style="font-weight:700; font-size:16px; color:#FFFFFF;">{threat_type.title()} Analysis</div>
        <div style="font-size:12px; color:#9CA3AF;">Generated: {timestamp}</div>
      </div>
    </div>
    <div style="text-align:right;">
      <div style="display:inline-block; padding:6px 10px; border-radius:999px; background:{sev_color}; color:#0b1220; font-weight:700;">{sev_label} • {severity}/100</div>
    </div>
  </div>
  <hr style="border:none; height:1px; background:#16324a; margin:12px 0;">
""")
        # If vt details in ctx, show small stat cards
        vt = ctx.get("vt_details") if isinstance(ctx, dict) else None
        if vt and isinstance(vt, dict):
            mcount = vt.get("malicious_count", vt.get("malicious") or 0)
            scount = vt.get("suspicious_count", vt.get("suspicious") or 0)
            hcount = vt.get("harmless_count", vt.get("harmless") or 0)
            und = vt.get("undetected_count", vt.get("undetected") or 0)
            total = vt.get("total", vt.get("total_engines") or (mcount + scount + hcount + und))
            # small grid
            html_parts.append(f"""
  <div style="display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap;">
    <div style="background:#0b1220; padding:10px; border-radius:8px; min-width:100px; border:1px solid #122233;">
      <div style="font-size:12px; color:#9CA3AF;">Malicious</div>
      <div style="font-weight:700; font-size:18px; color:#ff6961;">{mcount}</div>
    </div>
    <div style="background:#0b1220; padding:10px; border-radius:8px; min-width:100px; border:1px solid #122233;">
      <div style="font-size:12px; color:#9CA3AF;">Suspicious</div>
      <div style="font-weight:700; font-size:18px; color:#f59e0b;">{scount}</div>
    </div>
    <div style="background:#0b1220; padding:10px; border-radius:8px; min-width:100px; border:1px solid #122233;">
      <div style="font-size:12px; color:#9CA3AF;">Harmless</div>
      <div style="font-weight:700; font-size:18px; color:#34d399;">{hcount}</div>
    </div>
    <div style="background:#0b1220; padding:10px; border-radius:8px; min-width:120px; border:1px solid #122233;">
      <div style="font-size:12px; color:#9CA3AF;">Total engines</div>
      <div style="font-weight:700; font-size:18px; color:#93c5fd;">{total}</div>
    </div>
  </div>
""")
        # Sections
        for title, items in sections:
            html_parts.append(f"""<div style="margin-top:8px;"><div style="font-weight:700; color:#cbd5e1; margin-bottom:6px;">{title}</div>""")
            if items:
                html_parts.append("<ul style='margin:0 0 8px 18px; padding:0;'>")
                for it in items:
                    safe = self._escape_html(it)
                    html_parts.append(f"<li style='margin-bottom:6px; color:#dbeafe; font-size:14px;'>{safe}</li>")
                html_parts.append("</ul>")
            else:
                html_parts.append("<div style='color:#9ca3af; font-size:13px;'>No information available.</div>")
            html_parts.append("</div>")

        # Footer recommendations: quick buttons (rendered as spans)
        html_parts.append(f"""
  <hr style="border:none; height:1px; background:#16324a; margin:12px 0;">
  <div style="display:flex; gap:8px; flex-wrap:wrap;">
    <div style="background:{theme_color}; color:#041024; padding:8px 12px; border-radius:8px; font-weight:700;">Quick Action: Block domain</div>
    <div style="background:#0b1220; color:#9CA3AF; padding:8px 12px; border-radius:8px;">Scan endpoints</div>
    <div style="background:#0b1220; color:#9CA3AF; padding:8px 12px; border-radius:8px;">Reset credentials</div>
  </div>
""")
        # end container
        html_parts.append("</div>")
        return "\n".join(html_parts)

    # -------------------------
    # Helpers
    # -------------------------
    def _clean_text(self, t: Any) -> str:
        if t is None:
            return ""
        if isinstance(t, dict) or isinstance(t, list):
            try:
                return json.dumps(t, indent=2)
            except:
                return str(t)
        return str(t).strip()

    def _severity_line(self, sev: int) -> str:
        return f"Severity Rating: {severity_label(sev)} ({sev}/100)"

    def _escape_html(self, s: str) -> str:
        return (s.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;")
                 .replace('"', "&quot;"))

    # -------------------------
    # Final fallback (enhanced)
    # -------------------------
    def _final_fallback(self, threat_type: str, ctx: Dict[str, Any]) -> RAGExplanationResponse:
        theme = ExplanationTheme.get_theme(threat_type)
        plain = (
            "Threat Overview:\n"
            f"• Heuristic fallback executed for {threat_type}\n\n"
            "Immediate Impact:\n"
            "• Unknown impact due to AI failure\n\n"
            "Attack Chain:\n"
            "• No attack pattern identified\n\n"
            "Evidence Summary:\n"
            f"• Context sample: {str(ctx)[:250]}\n\n"
            "How Dangerous It Is:\n"
            "• Potentially harmful\n\n"
            "How To Stay Safe:\n"
            "• Do not interact with suspicious links\n\n"
            "How To Avoid This Threat:\n"
            "• Enable DNS filtering and update antivirus\n\n"
            "Recommended Actions:\n"
            "• Block domain\n"
            "• Reset credentials\n"
            "• Run endpoint scan\n\n"
            f"{self._severity_line(50)}"
        )
        html = self._build_html_from_structured(plain, threat_type, theme, 50, ctx)
        resp = RAGExplanationResponse(
            explanation_id=None,
            generated_at=datetime.utcnow(),
            short_summary=f"{theme['icon']} {threat_type} detected",
            summary="AI unavailable — heuristic fallback used.",
            full_explanation=plain,
            severity=50,
            mitre_techniques=[]
        )
        try:
            setattr(resp, "full_explanation_html", html)
        except:
            pass
        return resp

    # -------------------------
    # Health / status
    # -------------------------
    def get_status(self) -> Dict[str, Any]:
        return {
            "gemini_ready": self.gemini_ready,
            "openai_ready": self.openai_ready,
            "init_error": self.init_error,
            "cache_size": len(self.explanation_cache),
            "timestamp": datetime.utcnow().isoformat()
        }
