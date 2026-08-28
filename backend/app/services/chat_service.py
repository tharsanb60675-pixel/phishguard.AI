"""
PhishGuard AI Helpline — Real Conversational AI Integration.
Connects with OpenAI (or OpenAI-compatible providers) for multi-turn cybersecurity dialogues,
incorporating active scan context, URL engine verdicts, credential guardrails, and incident containment.
"""

import re
import uuid
import httpx
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from app.core.config import settings
from app.schemas.chat import ChatRequest, ChatResponse
from app.services.scan_service import scan_service


# ─── Prohibited Sensitive Credential Patterns ────────────────────────────────
SENSITIVE_SECRET_PATTERNS = [
    r'\b(?:\d{6}|\d{4})\b.*(?:otp|pin|passcode|code)',
    r'(?:my\s+(?:password|pin|otp|cvv|upi|card\s*number)\s+is\s+[:=]?\s*\S+)',
    r'\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b',
    r'\b(?:\d{3}|\d{4})\b.*(?:cvv|cvc|security\s*code)',
]

SYSTEM_PROMPT_TEMPLATE = """You are PhishGuard AI Helpline, a cybersecurity assistance chatbot.

Your job is to help users understand suspicious QR codes, barcodes, URLs, websites, emails, SMS messages, WhatsApp messages, phishing attempts, social-engineering attacks, payment scams, fake customer-support messages, fake bank messages, and other online-security threats.

Key Guidelines:
1. Give clear, simple, practical, and non-technical cybersecurity guidance.
2. Use the scan/threat-analysis information provided by PhishGuard AI as context whenever available.
3. NEVER ask users to provide passwords, OTPs, PINs, CVVs, recovery codes, API keys, private keys, banking credentials, or other secrets.
4. If a user attempts to share sensitive credentials or says someone asked for them, immediately emphasize that they must NEVER disclose them.
5. Do not invent scan results. Clearly distinguish between information detected by the PhishGuard threat engine and your own explanation.
6. If a user says they already clicked a link or entered details, provide a calm, reassuring 5-step containment checklist (1. Change password via official site, 2. Enable MFA, 3. Terminate sessions, 4. Contact bank if financial, 5. Run malware scan).
7. If there is insufficient information, ask what additional non-sensitive details are available (e.g. sender domain, exact wording with secrets masked).
8. Remain calm, professional, friendly, concise, and easy to understand.
"""


class ChatService:
    @staticmethod
    def check_for_sensitive_secrets(user_input: str) -> Optional[str]:
        """Detect if the user is accidentally typing a private secret (password, OTP, PIN, CVV)."""
        low = user_input.lower()
        for pat in SENSITIVE_SECRET_PATTERNS:
            if re.search(pat, low):
                return (
                    "⚠️ **Please do not share sensitive information.**\n\n"
                    "For your security, **never send passwords, OTPs, UPI PINs, CVVs, full card numbers, recovery codes, or banking credentials** to this chatbot or anyone else.\n\n"
                    "You can describe your problem safely without including the actual secret."
                )

        if "my password is" in low or "my pin is" in low or "my otp is" in low or "my cvv is" in low:
            return (
                "⚠️ **Please do not share your private credentials.**\n\n"
                "I am designed to protect you, but you should never disclose raw passwords, OTP codes, PINs, or card details in any chat. Please describe what happened generally."
            )

        return None

    @classmethod
    async def call_openai_api(
        cls,
        messages: List[Dict[str, str]],
        api_key: str,
        base_url: str,
        model: str
    ) -> Optional[str]:
        """Execute real asynchronous chat completion with OpenAI or OpenAI-compatible endpoint."""
        url = f"{base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.5,
            "max_tokens": 800,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            res = await client.post(url, headers=headers, json=payload)
            if res.status_code == 200:
                data = res.json()
                if "choices" in data and len(data["choices"]) > 0:
                    return data["choices"][0]["message"]["content"].strip()
            else:
                error_body = res.text
                print(f"[PhishGuard AI Helpline] OpenAI API returned HTTP {res.status_code}: {error_body}")
                return None

    @staticmethod
    def build_system_context(scan_ctx: Optional[Dict[str, Any]]) -> str:
        """Construct the contextual system instruction including the active scan metadata."""
        sys_prompt = SYSTEM_PROMPT_TEMPLATE

        if scan_ctx:
            format_name = scan_ctx.get("formatName") or scan_ctx.get("type", "Code")
            raw_val = scan_ctx.get("rawValue", "")
            risk_score = scan_ctx.get("riskScore", 0)
            verdict = scan_ctx.get("verdict", "UNKNOWN")
            reasons = scan_ctx.get("reasons") or []
            advice = scan_ctx.get("actionableAdvice", "")

            sys_prompt += f"\n\n--- ACTIVE PHISHGUARD SCAN CONTEXT ---"
            sys_prompt += f"\n- Scanned Target Type: {format_name}"
            sys_prompt += f"\n- Decoded Target / URL: {raw_val}"
            sys_prompt += f"\n- Risk Score: {risk_score:.1f} / 100"
            sys_prompt += f"\n- Verdict: {verdict}"
            if reasons:
                sys_prompt += f"\n- Detected Reasons: {', '.join(reasons)}"
            if advice:
                sys_prompt += f"\n- Initial Engine Advice: {advice}"
            sys_prompt += "\nUse this active scan context whenever the user asks questions about 'this', 'the QR code', 'the URL', or the scanned item."

        return sys_prompt

    @classmethod
    async def process_chat(
        cls,
        mongo_db: Any,
        user_id: int,
        req: ChatRequest
    ) -> ChatResponse:
        session_id = req.session_id or f"sess_{uuid.uuid4().hex[:10]}"
        user_text = req.message.strip()
        msg_lower = user_text.lower()

        # 1. First line of defense: Check for accidental credential disclosure
        secret_warning = cls.check_for_sensitive_secrets(user_text)
        if secret_warning:
            return ChatResponse(
                session_id=session_id,
                response=secret_warning,
                detected_threats=["Sensitive Credential Disclosure Warning"],
                recommended_action="Keep credentials strictly private and never disclose PINs or OTPs in chat.",
                sources=["PhishGuard Privacy & Safety Protocol"],
                threat_level="HIGH",
                is_live_ai=False
            )

        # 2. Check if a URL was pasted in message -> run through PhishGuard threat engine for live enrichment
        url_match = re.search(r'(https?://[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}[^\s]*)', user_text)
        engine_enrichment = ""
        if url_match and not url_match.group(0).startswith("sess_"):
            try:
                target_url = url_match.group(0)
                pre_check = await scan_service.pre_click_check(target_url)
                engine_enrichment = (
                    f"\n[PhishGuard Threat Engine Scan for '{target_url}': "
                    f"Verdict: {pre_check.verdict}, Risk Score: {pre_check.risk_score}/100, "
                    f"Explanation: {pre_check.explanation_summary}]"
                )
            except Exception:
                pass

        # 3. Build Conversation Messages Payload for Real LLM
        system_instruction = cls.build_system_context(req.scan_context)
        if engine_enrichment:
            system_instruction += f"\n\n--- INCOMING URL SCAN EVALUATION ---{engine_enrichment}"

        llm_messages = [{"role": "system", "content": system_instruction}]

        # Inject conversation history (up to last 12 messages)
        if req.history and isinstance(req.history, list):
            for h in req.history[-12:]:
                r = h.get("role", "user")
                c = h.get("content", "")
                if c and r in ["user", "assistant"]:
                    llm_messages.append({"role": r, "content": c})

        # Append latest user query
        llm_messages.append({"role": "user", "content": user_text})

        # 4. Attempt Real LLM Generation via OpenAI API
        api_key = settings.effective_openai_key
        base_url = settings.OPENAI_BASE_URL
        model = settings.OPENAI_MODEL or "gpt-4o-mini"

        if api_key and api_key.strip() and not api_key.startswith("your_"):
            try:
                ai_text = await cls.call_openai_api(
                    messages=llm_messages,
                    api_key=api_key.strip(),
                    base_url=base_url,
                    model=model
                )
                if ai_text:
                    # Persist conversation to MongoDB
                    try:
                        chat_entry = {
                            "user_id": user_id,
                            "session_id": session_id,
                            "user_message": user_text,
                            "assistant_response": ai_text,
                            "scan_context": req.scan_context,
                            "is_live_ai": True,
                            "model": model,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                        await mongo_db["chatbot_conversations"].insert_one(chat_entry)
                    except Exception:
                        pass

                    return ChatResponse(
                        session_id=session_id,
                        response=ai_text,
                        detected_threats=["AI Evaluated Cyber Query"],
                        recommended_action="Follow the guidance provided by the AI Helpline.",
                        sources=[f"PhishGuard AI Helpline ({model})", "NIST Security Framework"],
                        threat_level="MEDIUM" if "suspicious" in ai_text.lower() or "danger" in ai_text.lower() else "INFO",
                        is_live_ai=True,
                        ai_provider="openai"
                    )
            except Exception as e:
                print(f"[PhishGuard AI Helpline] LLM generation exception: {e}")

        # 5. Local Cyber Defense Reasoning Engine (Fallback if OPENAI_API_KEY is not set)
        scan_ctx = req.scan_context
        if scan_ctx and any(w in msg_lower for w in ["why", "dangerous", "risk", "what is this", "explain", "safe"]):
            code_type = scan_ctx.get("formatName") or scan_ctx.get("type", "QR Code")
            verdict = scan_ctx.get("verdict", "UNKNOWN")
            risk_score = scan_ctx.get("riskScore", 0)
            raw_value = scan_ctx.get("rawValue", "")

            if verdict in ["MALICIOUS", "ZERO_DAY"] or risk_score >= 70:
                response_text = (
                    f"🤖 **Scan Diagnosis ({code_type}):**\n\n"
                    f"This {code_type} leads to `{raw_value}`, which was classified as **{verdict}** with a **Risk Score of {risk_score:.1f}/100** by PhishGuard AI.\n\n"
                    f"**Why this is dangerous:**\n"
                    f"• The destination domain exhibits suspicious credential-harvesting characteristics.\n"
                    f"• It is likely designed to impersonate a legitimate service to capture your login or banking information.\n\n"
                    f"**Recommended Steps:**\n"
                    f"1. **Do not open the link or scan authentication requests for it.**\n"
                    f"2. If this was sent to you unexpectedly, block the sender.\n"
                    f"3. Never enter OTPs or passwords on unverified domains."
                )
            elif verdict == "SUSPICIOUS" or risk_score >= 40:
                response_text = (
                    f"🤖 **Scan Diagnosis ({code_type}):**\n\n"
                    f"The scanned link `{raw_value}` has an elevated **Risk Score of {risk_score:.1f}/100**.\n\n"
                    f"**Key Findings:**\n"
                    f"• The website name or domain obscurity structure looks atypical.\n"
                    f"• It may be an unverified landing page.\n\n"
                    f"**Advice:** Only proceed if you personally recognize this exact domain."
                )
            else:
                response_text = (
                    f"🤖 **Scan Diagnosis ({code_type}):**\n\n"
                    f"The {code_type} payload (`{raw_value}`) was verified as **SAFE** with a low risk score of **{risk_score:.1f}/100**.\n\n"
                    f"No known phishing indicators, domain anomalies, or credential harvesting triggers were found."
                )
        elif any(w in msg_lower for w in ["clicked", "already clicked", "entered details", "entered password"]):
            response_text = (
                "**Don't panic.** Here is your immediate incident response checklist:\n\n"
                "1. **Change Passwords Immediately:** Go directly to the official website or app of the affected account (do NOT use links from the message) and change your password.\n"
                "2. **Enable Multi-Factor Authentication (MFA):** Turn on 2FA or passkeys immediately.\n"
                "3. **Review Account Sessions:** Go to account security settings and choose *'Log out of all other devices'*.\n"
                "4. **If Financial Details were Shared:** Contact your bank or card issuer immediately via the phone number on your card to lock the card.\n"
                "5. **Avoid Downloads:** If a file was downloaded, delete it and do not run it."
            )
        elif any(w in msg_lower for w in ["otp", "one-time password", "verification code"]):
            response_text = (
                "**Never share your OTP with anyone.**\n\n"
                "A legitimate bank, delivery carrier, or customer support team will **NEVER** ask you to disclose an OTP, UPI PIN, or SMS code over chat, phone, or email.\n\n"
                "If someone is demanding an OTP, it is almost certainly a scam attempting to take over your account."
            )
        elif any(w in msg_lower for w in ["bank", "account suspended", "kyc", "blocked"]):
            response_text = (
                "Urgent notices claiming your bank account is suspended or requiring immediate KYC verification are classic phishing lures.\n\n"
                "**What to do:**\n"
                "• Do not tap links inside the message.\n"
                "• Contact your bank using the phone number printed on the back of your official debit/credit card."
            )
        elif engine_enrichment:
            response_text = (
                f"I analyzed the destination URL using PhishGuard's threat engine:\n"
                f"{engine_enrichment}\n\n"
                f"**Recommendation:** Do not enter any login credentials or personal information on unverified sites."
            )
        else:
            response_text = (
                "I am your PhishGuard AI Cybersecurity Helpline. I can help you evaluate suspicious QR codes, "
                "URLs, SMS texts, WhatsApp messages, and fake bank communications.\n\n"
                "You can ask me questions like:\n"
                "• *'Why is this QR code dangerous?'*\n"
                "• *'Someone asked for my OTP on WhatsApp, is that safe?'*\n"
                "• *'I already clicked a suspicious link, what should I do?'*\n"
                "• Or paste any URL or message text here for threat analysis."
            )

        return ChatResponse(
            session_id=session_id,
            response=response_text,
            detected_threats=["Cybersecurity Guidance"],
            recommended_action="Remain cautious and verify suspicious requests through official channels.",
            sources=["PhishGuard AI Threat Engine", "NIST Cybersecurity Framework"],
            threat_level="INFO",
            is_live_ai=False,
            ai_provider="local_engine"
        )


chat_service = ChatService()
