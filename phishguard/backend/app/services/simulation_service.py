"""
AI Scam Simulation & Adaptive Learning Service.
Generates realistic, targeted phishing simulations tailored to user risk tier,
evaluates user actions (Reporting vs Clicking vs Falling for attack), and updates user vulnerability metrics.
"""

from typing import List, Optional, Any
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.models.user import User
from app.ml.vulnerability_model import vulnerability_engine
from app.schemas.simulation import (
    SimulationScenario,
    SimulationActionRequest,
    SimulationActionResponse
)


SIMULATION_SCENARIOS = [
    SimulationScenario(
        id="sim_payroll_01",
        theme="Urgent Payroll Direct Deposit Confirmation",
        difficulty="Novice",
        sender_name="HR & Payroll Services",
        sender_email="payroll-updates@corp-internal-portal.xyz",
        subject="[Action Required] Verification of Pending Direct Deposit Details",
        body_html="""<div style="font-family: sans-serif; padding: 15px; color: #1e293b;">
            <p>Dear Employee,</p>
            <p>During our routine bi-weekly payroll audit, your direct deposit banking information failed automated ACH validation.</p>
            <p style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 10px; margin: 15px 0;">
                <strong>Deadline Notice:</strong> To ensure your upcoming paycheck is not held for 14 business days, please verify your bank credentials immediately.
            </p>
            <p><a href="https://verify-payroll-identity.corp-portal.xyz/login" style="background: #2563eb; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Update Direct Deposit Now</a></p>
            <p>Regards,<br>Human Resources & Compensation Team</p>
        </div>""",
        red_flags=[
            "External sender domain (.xyz extension instead of internal corporate domain)",
            "Artificial urgency and threat of withholding salary",
            "Direct link requesting banking credential verification"
        ],
        explanation="This is a classic payroll spear-phishing attack. Real corporate HR systems never threaten immediate salary forfeiture via generic email links."
    ),
    SimulationScenario(
        id="sim_mfa_02",
        theme="Critical Security Team: 2FA Device Re-authentication",
        difficulty="Intermediate",
        sender_name="Global IT Infrastructure & Security",
        sender_email="admin-secops@auth-gateway-sso.cloud",
        subject="[ALERT] Mandatory Security Patch: Re-sync Authenticator App",
        body_html="""<div style="font-family: sans-serif; padding: 15px; color: #1e293b;">
            <p>Attention Team,</p>
            <p>Due to recent zero-day vulnerability exploits in enterprise SSO gateways, all staff are required to re-authenticate their secondary MFA device.</p>
            <p>Failure to complete synchronization within 4 hours will result in automatic network lockdown.</p>
            <p><a href="https://sso-auth-sync.gateway-cloud.top/mfa" style="background: #059669; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Sync 2FA Token</a></p>
            <p>IT Security Operations Center</p>
        </div>""",
        red_flags=[
            "Suspicious top-level domain (.top)",
            "Generic urgency timeout ('within 4 hours')",
            "Requests out-of-band MFA verification via non-standard SSO URL"
        ],
        explanation="Attackers frequently impersonate internal SecOps teams during publicized cyber incidents to deceive employees into yielding MFA tokens."
    ),
    SimulationScenario(
        id="sim_ceo_03",
        theme="Executive Impersonation (CEO Wire Request)",
        difficulty="Advanced",
        sender_name="Chief Executive Officer",
        sender_email="ceo.office.direct@gmail.com",
        subject="Confidential: Vendor Acquisition Escrow",
        body_html="""<div style="font-family: sans-serif; padding: 15px; color: #1e293b;">
            <p>Hi,</p>
            <p>I am currently boarding a flight to London for the acquisition closing and cannot take calls. I need you to initiate a confidential initial escrow disbursement of $48,500 to the legal retainer account today before market close.</p>
            <p>Reply with your direct phone number so our external counsel can send the routing memo.</p>
            <p>Best,<br>Sent from my iPhone</p>
        </div>""",
        red_flags=[
            "Public Gmail address used instead of company email",
            "Bypasses standard dual-authorization financial controls",
            "High urgency combined with unavailability ('boarding a flight')"
        ],
        explanation="Business Email Compromise (BEC) attacks bypass automated URL filters by using pure text and social pressure to trigger fraudulent wires."
    )
]


class SimulationService:
    @staticmethod
    def get_scenarios_for_user(user_tier: str) -> List[SimulationScenario]:
        return SIMULATION_SCENARIOS

    @staticmethod
    async def process_user_action(
        db: AsyncSession,
        mongo_db: Any,
        user: User,
        req: SimulationActionRequest
    ) -> SimulationActionResponse:
        # Find scenario
        scenario = next((s for s in SIMULATION_SCENARIOS if s.id == req.simulation_id), SIMULATION_SCENARIOS[0])
        
        prev_vuln = user.vulnerability_index
        new_vuln, new_tier = vulnerability_engine.calculate_new_vulnerability(
            current_index=prev_vuln,
            action=req.user_action,
            response_time_seconds=req.response_time_seconds
        )

        # Update User in DB
        user.vulnerability_index = new_vuln
        user.risk_profile_tier = new_tier
        await db.commit()
        await db.refresh(user)

        # Log to MongoDB adaptive learning logs
        try:
            log_doc = {
                "user_id": user.id,
                "simulation_id": req.simulation_id,
                "user_action": req.user_action,
                "response_time_seconds": req.response_time_seconds,
                "previous_vuln": prev_vuln,
                "new_vuln": new_vuln,
                "new_tier": new_tier,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await mongo_db["adaptive_learning_logs"].insert_one(log_doc)
        except Exception:
            pass

        correct = req.user_action.upper() in ["REPORTED", "IGNORED"]
        
        if req.user_action.upper() == "REPORTED":
            title = "Outstanding Detection! Threat Neutralized"
            msg = f"You correctly identified the phishing simulation in {req.response_time_seconds:.1f}s. Your vulnerability index decreased to {new_vuln}."
        elif req.user_action.upper() == "IGNORED":
            title = "Threat Avoided"
            msg = "You avoided the trap. Pro-tip: Reporting simulations helps protect your entire organization."
        elif req.user_action.upper() == "CLICKED_LINK":
            title = "Warning: Phishing Link Clicked"
            msg = "In a real attack, this link could have downloaded malware or intercepted credentials. Study the red flags below."
        else:
            title = "Critical Breach: Credentials Submitted"
            msg = "You submitted simulated credentials on a fraudulent page. In an actual breach, accounts would require immediate revocation."

        return SimulationActionResponse(
            success=True,
            correct_action=correct,
            feedback_title=title,
            feedback_message=msg,
            previous_vulnerability_index=prev_vuln,
            new_vulnerability_index=new_vuln,
            updated_tier=new_tier,
            uncovered_red_flags=scenario.red_flags
        )


simulation_service = SimulationService()
