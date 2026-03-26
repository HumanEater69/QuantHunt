from __future__ import annotations

import os
import re

import httpx

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
GEMINI_URL_TMPL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

def _local_ai_recommendations(summary: str, base_recommendations: list[str]) -> list[str]:
    text = summary.lower()
    recs: list[str] = []
    if "tlsv1.0" in text or "tlsv1.1" in text:
        recs.append("Disable TLS 1.0/1.1 and enforce TLS 1.2+ with modern ciphers across all ingress points.")
    if "rsa" in text and "key_exchange=critical" in text:
        recs.append("Prioritize RSA key exchange retirement and move internet-facing endpoints to ECDHE-based handshakes.")
    if "auth=critical" in text or "auth=warning" in text:
        recs.append("Rotate certificates to stronger signature profiles and maintain automated certificate expiry monitoring.")
    if "score=" in text:
        m = re.search(r"score=([0-9]+(?:\.[0-9]+)?)", text)
        if m and float(m.group(1)) > 80:
            recs.append("Treat this asset as priority-1 in your PQC roadmap with a tracked remediation owner and SLA.")
    for rec in base_recommendations:
        if len(recs) >= 3:
            break
        if rec not in recs:
            recs.append(rec)
    return recs[:3]

async def _recommend_with_gemini(asset: str, summary: str, base_recommendations: list[str]) -> list[str]:
    api_key = os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    if not api_key:
        return _local_ai_recommendations(summary, base_recommendations)

    url = GEMINI_URL_TMPL.format(model=model, api_key=api_key)
    prompt = (
        "You are a cybersecurity consultant for internet-exposed infrastructure. "
        "Return exactly 3 concise remediation actions for a post-quantum migration roadmap.\n\n"
        f"Asset: {asset}\nSummary: {summary}\n"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 220},
    }
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            lines: list[str] = []
            for cand in data.get("candidates", []):
                content = cand.get("content") or {}
                for part in content.get("parts", []):
                    text = part.get("text")
                    if isinstance(text, str):
                        for line in text.splitlines():
                            cleaned = line.strip().lstrip("-*").strip()
                            if len(cleaned) > 8:
                                lines.append(cleaned)
            out: list[str] = []
            for item in lines:
                if item not in out:
                    out.append(item)
                if len(out) == 3:
                    break
            return out if out else _local_ai_recommendations(summary, base_recommendations)
    except Exception:
        return _local_ai_recommendations(summary, base_recommendations)

async def recommend_with_claude(asset: str, summary: str, base_recommendations: list[str]) -> list[str]:
    gemini_first = await _recommend_with_gemini(asset, summary, base_recommendations)
    if os.getenv("GEMINI_API_KEY"):
        return gemini_first

    api_key = os.getenv("ANTHROPIC_API_KEY")
    model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
    if not api_key:
        return gemini_first

    prompt = (
        "You are a cybersecurity consultant for banking infrastructure. "
        "Given this finding summary, return exactly 3 concise actionable migration steps "
        "for a post-quantum transition roadmap.\n\n"
        f"Asset: {asset}\nSummary: {summary}\n"
    )

    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 280,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(ANTHROPIC_URL, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            text = ""
            for block in data.get("content", []):
                if block.get("type") == "text":
                    text += block.get("text", "")
            lines = [x.strip("- ").strip() for x in text.splitlines() if x.strip()]
            cleaned = [l for l in lines if len(l) > 8][:3]
            return cleaned if cleaned else gemini_first
    except Exception:
        return gemini_first
