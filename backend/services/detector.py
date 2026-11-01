"""Email spam and phishing detection engine.

Implements an explainable, modular heuristic baseline detector with clear rule attribution,
and provides an abstract interface for plugging in trained AI/ML models (e.g. Scikit-learn,
HuggingFace Transformers) in the future without changing API routes or database models.
"""

import re
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple


class BaseDetectionEngine(ABC):
    """Abstract base class for email threat detection engines."""

    @abstractmethod
    def analyze(
        self,
        from_addr: str,
        reply_to: Optional[str],
        subject: str,
        body: str,
        attachment: Optional[str],
        threshold: float = 0.5,
    ) -> Dict[str, Any]:
        """Analyze an email and return classification, score, confidence, and reasons."""
        pass


class HeuristicBaselineDetector(BaseDetectionEngine):
    """Modular, rule-based baseline detector matching MailGuard's security heuristic logic.

    Attributes:
        reputation: Domain reputation store containing domain age (in days) and prior report counts.
        bad_tld_pattern: Regex matching high-risk top-level domains.
        brands: List of commonly spoofed institutions/brands.
    """

    DEFAULT_REPUTATION: Dict[str, Dict[str, Any]] = {
        "company.com": {"age": 2400, "rep": 0},
        "hdfcbank.com": {"age": 9000, "rep": 0},
        "secure-bank-verify.xyz": {"age": 6, "rep": 31},
        "micros0ft-support.com": {"age": 11, "rep": 18},
        "prize-claim.top": {"age": 4, "rep": 44},
        "deals-mart.biz": {"age": 120, "rep": 6},
    }

    BAD_TLD_REGEX = re.compile(r"\.(xyz|top|biz|click|ru|work|zip|info)$", re.IGNORECASE)
    BRANDS = ["bank", "paypal", "microsoft", "amazon", "google", "hdfc", "sbi", "icici"]
    URL_REGEX = re.compile(r"https?://([^\s/]+)", re.IGNORECASE)
    KEYWORD_REGEX = re.compile(r"lottery|winner|viagra|free money|claim your prize", re.IGNORECASE)
    RISKY_ATTACHMENTS = re.compile(r"\.(exe|zip|html|scr|js)$", re.IGNORECASE)

    # Heuristic pattern categories
    URGENT_REGEX = re.compile(
        r"urgent|immediately|suspended|blocked|within 24|expire|final notice",
        re.IGNORECASE,
    )
    CREDENTIAL_REGEX = re.compile(
        r"kyc|password|otp|verify|log ?in|sign in|card number|\bpin\b|update.*details",
        re.IGNORECASE,
    )
    PRIZE_REGEX = re.compile(
        r"\bwon\b|lottery|lakh|prize|claim|inheritance",
        re.IGNORECASE,
    )
    PROMO_REGEX = re.compile(
        r"% off|sale|buy now|limited time|unsubscribe|discount",
        re.IGNORECASE,
    )
    TYPOSQUAT_REGEX = re.compile(r"[a-z]0[a-z]|[a-z]1[a-z]", re.IGNORECASE)

    def __init__(self, reputation_override: Optional[Dict[str, Dict[str, Any]]] = None):
        self.reputation = reputation_override or self.DEFAULT_REPUTATION.copy()

    def update_reputation(self, domain: str, age: Optional[int] = None, add_reports: int = 1) -> None:
        """Update or register domain reputation counters."""
        d = domain.lower()
        if d not in self.reputation:
            self.reputation[d] = {"age": age, "rep": add_reports}
        else:
            self.reputation[d]["rep"] += add_reports
            if age is not None:
                self.reputation[d]["age"] = age

    def analyze(
        self,
        from_addr: str,
        reply_to: Optional[str],
        subject: str,
        body: str,
        attachment: Optional[str],
        threshold: float = 0.77,
    ) -> Dict[str, Any]:
        """Perform comprehensive heuristic analysis on the email message."""
        t0 = time.perf_counter()
        from_clean = from_addr.strip().lower()
        reply_clean = (reply_to or "").strip().lower()
        sub_clean = subject or ""
        body_clean = body or ""
        combined_text = (sub_clean + " " + body_clean).lower()

        why: List[Dict[str, Any]] = []
        fraud_score = 0.0
        spam_score = 0.0

        def add_indicator(kind: str, weight: float, message: str):
            nonlocal fraud_score, spam_score
            why.append({"bad": True, "msg": message})
            if kind == "f":
                fraud_score += weight
            else:
                spam_score += weight

        # 1. Content Analysis
        if self.URGENT_REGEX.search(combined_text):
            add_indicator("f", 0.22, "Urgent or threatening wording pushes you to act fast.")

        if self.CREDENTIAL_REGEX.search(combined_text):
            add_indicator("f", 0.20, "Asks for credentials or personal details.")

        if self.PRIZE_REGEX.search(combined_text):
            add_indicator("f", 0.30, "Prize or money claim, a classic scam pattern.")

        if self.PROMO_REGEX.search(combined_text):
            add_indicator("s", 0.40, "Promotional wording typical of bulk spam.")

        # 2. Sender Domain and Reputation
        sender_domain = from_clean.split("@")[-1] if "@" in from_clean else ""
        rep_info = self.reputation.get(sender_domain, {"age": None, "rep": 0})

        # 3. URL Extraction and High-Risk TLDs
        extracted_hosts = [m.group(1).lower() for m in self.URL_REGEX.finditer(combined_text)]
        for host in extracted_hosts:
            if self.BAD_TLD_REGEX.search(host):
                add_indicator("f", 0.20, f"Link domain {host} uses a high-risk ending.")

        # 4. Brand Impersonation & Link Mismatch
        # Only check if sender domain does not belong to the brand itself
        matched_brand = next(
            (b for b in self.BRANDS if b in combined_text and not sender_domain.endswith(f"{b}.com")),
            None,
        )
        if matched_brand:
            mismatched_link = next(
                (h for h in extracted_hosts if not h.startswith(f"{matched_brand}.") and not h.endswith(f"{matched_brand}.com") and not h.endswith(sender_domain)),
                None,
            )
            if mismatched_link and not sender_domain.startswith(f"{matched_brand}."):
                add_indicator("f", 0.20, f'Mentions "{matched_brand}" but the link goes to {mismatched_link}.')

        # 5. Typosquatting / Character Substitution in Domain
        domain_sld = sender_domain.split(".")[0] if "." in sender_domain else sender_domain
        if self.TYPOSQUAT_REGEX.search(domain_sld):
            add_indicator("f", 0.30, f"Sender domain {sender_domain} imitates a known brand (digit swapped for a letter).")

        # 6. Domain Age and Historical Reports
        age = rep_info.get("age")
        if age is not None and age < 60:
            add_indicator("f", 0.15, f"Sender domain registered only {age} days ago.")

        reports = rep_info.get("rep", 0)
        if reports > 0:
            kind = "f" if reports > 10 else "s"
            add_indicator(kind, 0.20, f"Sender domain reported {reports} times by other users.")

        # 7. Reply-To Mismatch
        if reply_clean and "@" in reply_clean:
            reply_domain = reply_clean.split("@")[-1]
            if reply_domain != sender_domain:
                add_indicator("f", 0.20, f"Reply-to ({reply_clean}) differs from the sender domain.")

        # 8. Attachment Threat Evaluation
        if attachment and attachment.strip():
            att_clean = attachment.strip()
            if self.RISKY_ATTACHMENTS.search(att_clean):
                add_indicator("f", 0.20, f"Risky attachment type: {att_clean}.")

        # 9. Verdict Determination & Score Normalization
        total_score = min(1.0, fraud_score + spam_score)
        verdict_type = "fraud" if fraud_score >= spam_score else "spam"

        if total_score < 0.30:
            verdict_type = "safe"
            why.clear()
            why.append({
                "bad": False,
                "msg": "Wording looks normal and no risky links or attachments were found.",
            })
            if age is not None and age > 365:
                years = round(age / 365)
                why.append({
                    "bad": False,
                    "msg": f"Sender domain is established ({years}+ years) with no reports.",
                })

        # Calculate Confidence
        if verdict_type == "safe":
            confidence = int(round((1.0 - total_score) * 100))
        else:
            confidence = min(99, int(round(55 + total_score * 45)))

        # Plain Keyword Filter Check (for baseline comparison)
        kw_flag = bool(self.KEYWORD_REGEX.search(combined_text))

        # Enforce Action Based on Sensitivity Threshold
        if verdict_type != "safe" and total_score >= threshold:
            action = "blocked"
        elif verdict_type != "safe":
            action = "flagged"
        else:
            action = "delivered"

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        return {
            "score": round(total_score, 3),
            "type": verdict_type,
            "conf": confidence,
            "why": why,
            "ms": f"{latency_ms:.1f}",
            "latency_ms_num": latency_ms,
            "kwFlag": kw_flag,
            "action": action,
            "detection_version": "heuristic-baseline-1.0",
        }


# Global detector instance
detector = HeuristicBaselineDetector()
