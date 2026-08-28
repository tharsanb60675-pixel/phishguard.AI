"""
Threat Scan & Orchestration Service.
Coordinates feature extraction, multi-model inference (Phishing Classifier + Zero-Day Anomaly Detector),
SHAP explainability calculations, and dual-database persistence (MySQL metadata + MongoDB payloads).
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.models.user import User
from app.models.scan_history import ScanHistory, ScanVerdict, ScanType
from app.models.risk_score_log import RiskScoreLog
from app.ml.feature_extraction import extract_url_features
from app.ml.phishing_detector import phishing_detector
from app.ml.zero_day_detector import zero_day_detector
from app.ml.shap_explainer import shap_threat_explainer
from app.ml.social_engineering_nlp import social_engineering_analyzer
from app.schemas.scan import (
    ThreatScanRequest,
    ThreatScanResponse,
    ThreatScoreBreakdown,
    PreClickCheckResponse
)


class ScanService:
    @staticmethod
    async def execute_scan(
        db: AsyncSession,
        mongo_db: Any,
        user: User,
        req: ThreatScanRequest
    ) -> ThreatScanResponse:
        start_time = time.perf_counter()

        # Step 1: Feature Extraction
        features = extract_url_features(req.target)
        
        # Step 2: Multi-Model Inference
        # A. Phishing Classifier
        phishing_prob, _ = phishing_detector.predict_proba(features)

        # B. Zero-Day Anomaly Detection
        zero_day_score, is_zero_day = zero_day_detector.calculate_anomaly_score(features)

        # C. NLP Social Engineering Score (if text or URL has explicit token string)
        nlp_res = social_engineering_analyzer.analyze(req.target)
        social_eng_score = nlp_res.overall_manipulation_score

        # Step 3: Personalized Risk Calculation
        # User Risk Tier Multipliers:
        # Novice: 1.15 (more cautious / elevated alerts)
        # Intermediate: 1.00 (standard balance)
        # Advanced: 0.90 (tolerant / focused on technical indicators)
        # High-Risk: 1.25 (elevated vulnerability guard)
        tier_multipliers = {
            "Novice": 1.15,
            "Intermediate": 1.00,
            "Advanced": 0.90,
            "High-Risk": 1.25
        }
        user_tier = user.risk_profile_tier or "Novice"
        user_mult = tier_multipliers.get(user_tier, 1.0)

        # Weighted calculation: Phishing (40%) + Zero-Day (30%) + Social Eng (15%) + Base Vuln Index (15%)
        base_raw_score = (
            (phishing_prob * 0.40) +
            (zero_day_score * 0.30) +
            (social_eng_score * 0.15) +
            (user.vulnerability_index * 0.15)
        ) * 100.0

        final_score = round(min(100.0, max(0.0, base_raw_score * user_mult)), 1)

        # Determine Final Verdict
        if is_zero_day and final_score >= 65.0:
            verdict = ScanVerdict.ZERO_DAY.value
            risk_level = "CRITICAL"
        elif final_score >= 70.0:
            verdict = ScanVerdict.MALICIOUS.value
            risk_level = "HIGH" if final_score < 88.0 else "CRITICAL"
        elif final_score >= 38.0:
            verdict = ScanVerdict.SUSPICIOUS.value
            risk_level = "MEDIUM"
        else:
            verdict = ScanVerdict.SAFE.value
            risk_level = "LOW"

        # Step 4: Explainable AI with SHAP
        explanation = shap_threat_explainer.explain_prediction(
            feature_dict=features,
            predicted_prob=phishing_prob,
            user_tier=user_tier
        )

        # Step 5: Persist to MongoDB (Unstructured raw payload & SHAP document)
        mongo_raw_id = None
        mongo_shap_id = None
        
        try:
            raw_doc = {
                "user_id": user.id,
                "scan_type": req.scan_type,
                "raw_target": req.target,
                "extracted_features": features,
                "model_versions": {
                    "phishing": "random_forest_v1.0",
                    "zero_day": "isolation_forest_v1.0",
                    "nlp": "rule_heuristic_v1.0"
                },
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            res_raw = await mongo_db["scan_raw_data"].insert_one(raw_doc)
            mongo_raw_id = str(res_raw.inserted_id)

            shap_doc = {
                "user_id": user.id,
                "target": req.target,
                "explanation": explanation.model_dump(),
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            res_shap = await mongo_db["shap_explanations"].insert_one(shap_doc)
            mongo_shap_id = str(res_shap.inserted_id)
        except Exception as e:
            # Resilient fallback if MongoDB storage encounters issue
            mongo_raw_id = f"fallback_{int(time.time())}"
            mongo_shap_id = f"fallback_shap_{int(time.time())}"

        # Step 6: Persist to Relational MySQL/SQLite Database
        scan_record = ScanHistory(
            user_id=user.id,
            scan_type=req.scan_type,
            target_identifier=req.target[:500],
            verdict=verdict,
            risk_score=final_score,
            mongo_raw_id=mongo_raw_id,
            mongo_shap_id=mongo_shap_id,
            scanned_at=datetime.now(timezone.utc)
        )
        db.add(scan_record)
        await db.flush()  # Populate scan_record.id

        # Record fine-grained score log
        score_log = RiskScoreLog(
            scan_history_id=scan_record.id,
            user_id=user.id,
            phishing_probability=phishing_prob,
            zero_day_anomaly_score=zero_day_score,
            social_eng_score=social_eng_score,
            user_risk_modifier=user_mult,
            final_weighted_score=final_score
        )
        db.add(score_log)
        await db.commit()
        await db.refresh(scan_record)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return ThreatScanResponse(
            scan_id=scan_record.id,
            target=req.target,
            scan_type=req.scan_type,
            verdict=verdict,
            risk_score=final_score,
            risk_level=risk_level,
            breakdown=ThreatScoreBreakdown(
                phishing_probability=phishing_prob,
                zero_day_anomaly_score=zero_day_score,
                social_engineering_score=social_eng_score,
                user_risk_modifier=user_mult,
                final_weighted_score=final_score
            ),
            explanation=explanation,
            extracted_features=features,
            mongo_raw_id=mongo_raw_id,
            mongo_shap_id=mongo_shap_id,
            scanned_at=scan_record.scanned_at,
            execution_time_ms=elapsed_ms
        )

    @staticmethod
    async def pre_click_check(url: str, user_tier: str = "Novice") -> PreClickCheckResponse:
        """Lightweight fast pre-click check for browser navigation intercepts."""
        features = extract_url_features(url)
        phishing_prob, _ = phishing_detector.predict_proba(features)
        zero_day_score, is_zero_day = zero_day_detector.calculate_anomaly_score(features)
        
        score = round(max(phishing_prob * 100.0, zero_day_score * 90.0), 1)
        should_block = score >= 55.0

        if should_block:
            verdict = "MALICIOUS" if score >= 70.0 else "SUSPICIOUS"
            reason = "Pre-Click Shield Intercepted: High threat indicators (suspicious keywords or domain age)."
            explanation = f"Detected high risk score ({score}/100). Opening this page could expose your browser or credentials."
        else:
            verdict = "SAFE"
            reason = "Target passed lexical & reputation heuristic tests."
            explanation = "No high-risk phishing indicators detected on destination URL."

        return PreClickCheckResponse(
            url=url,
            verdict=verdict,
            risk_score=score,
            should_block=should_block,
            reason=reason,
            explanation_summary=explanation
        )


scan_service = ScanService()
