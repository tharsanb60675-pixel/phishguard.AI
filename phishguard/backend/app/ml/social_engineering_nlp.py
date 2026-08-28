"""
Social Engineering NLP Analysis Engine.
Analyzes message text, emails, and SMS for psychological manipulation tactics,
urgency cues, authority impersonation, scarcity, and credential harvesting hooks.
"""

import re
from typing import Dict, Any, List
from app.schemas.nlp import NLPAnalyzeResponse, TacticScore


TACTIC_PATTERNS = {
    "Urgency & Pressure": {
        "keywords": [
            r"\b(urgent|urgently|immediately|within \d+ hours?|right away|act now|instant|deadline|promptly|asap|final notice|time[- ]sensitive)\b"
        ],
        "weight": 1.2,
        "desc": "Pressures the recipient to act quickly without thinking or verifying."
    },
    "Authority & Impersonation": {
        "keywords": [
            r"\b(it support|security team|fraud prevention|ceo|director|hr department|internal revenue|irs|federal|fbi|police|legal counsel|compliance)\b"
        ],
        "weight": 1.1,
        "desc": "Impersonates organizational or legal hierarchy to command unquestioned compliance."
    },
    "Fear & Intimidation": {
        "keywords": [
            r"\b(account suspended|permanently disabled|legal action|lawsuit|penalty|arrest|unauthorized transaction|hacked|security breach|compromised)\b"
        ],
        "weight": 1.3,
        "desc": "Instills panic about account loss, financial penalties, or legal repercussions."
    },
    "Scarcity & Greed (Bait)": {
        "keywords": [
            r"\b(lottery winner|exclusive prize|free gift card|crypto payout|bonus approved|claim reward|unclaimed funds|inheritance|limited offer)\b"
        ],
        "weight": 1.0,
        "desc": "Lures user with false promises of financial gain or exclusive rewards."
    },
    "Credential & Action Harvesting": {
        "keywords": [
            r"\b(click here|log in below|verify your credentials|confirm password|update bank details|scan qr code|download attachment|enable macros)\b"
        ],
        "weight": 1.4,
        "desc": "Prompts target to disclose sensitive credentials or download payloads."
    }
}


class SocialEngineeringAnalyzer:
    def analyze(self, text_content: str, sender_context: str = "") -> NLPAnalyzeResponse:
        full_text = f"{sender_context} {text_content}".lower()
        
        tactics_breakdown: List[TacticScore] = []
        weighted_scores = []

        for tactic_name, config in TACTIC_PATTERNS.items():
            detected_phrases = []
            hit_count = 0
            
            for pattern in config["keywords"]:
                matches = re.findall(pattern, full_text, re.IGNORECASE)
                if matches:
                    detected_phrases.extend(list(set(matches)))
                    hit_count += len(matches)

            # Calculate tactical intensity score 0.0 - 1.0
            if hit_count == 0:
                tactic_score = 0.0
            elif hit_count == 1:
                tactic_score = 0.55
            elif hit_count == 2:
                tactic_score = 0.80
            else:
                tactic_score = 0.95

            weighted_scores.append(tactic_score * config["weight"])

            tactics_breakdown.append(
                TacticScore(
                    tactic=tactic_name,
                    score=round(tactic_score, 2),
                    detected_phrases=detected_phrases,
                    description=config["desc"]
                )
            )

        # Composite overall manipulation score
        avg_score = sum(weighted_scores) / (sum(c["weight"] for c in TACTIC_PATTERNS.values()) or 1.0)
        overall_score = round(min(1.0, avg_score * 1.4), 2)
        is_se = overall_score >= 0.45

        # Determine threat category
        if overall_score >= 0.75:
            category = "Aggressive Phishing / Extortion"
            summary = "High-risk social engineering attack utilizing multiple coordinated psychological manipulation tactics."
            guidance = "Do not click any links, open attachments, or reply. Report this message to your security team immediately."
        elif overall_score >= 0.45:
            category = "Suspicious Social Engineering"
            summary = "Contains noticeable psychological pressure techniques (urgency or authority cues)."
            guidance = "Verify sender authenticity independently through a known phone number or trusted directory."
        else:
            category = "Benign / Low Manipulation"
            summary = "No significant social engineering manipulation patterns detected."
            guidance = "Standard communication profile. Exercise normal caution."

        return NLPAnalyzeResponse(
            overall_manipulation_score=overall_score,
            threat_category=category,
            is_social_engineering=is_se,
            tactics_breakdown=tactics_breakdown,
            summary_analysis=summary,
            remediation_guidance=guidance
        )


social_engineering_analyzer = SocialEngineeringAnalyzer()
