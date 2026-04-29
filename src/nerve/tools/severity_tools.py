#!/usr/bin/env python3


import json
import math
import requests
from typing import Type, Dict, Any, ClassVar

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from ..config import Config


# ============================================================================
# SCHEMAS
# ============================================================================

class CVSSInput(BaseModel):
    finding: Dict[str, Any] = Field(description="Vulnerability finding object to score")


# ============================================================================
# CVSS CALCULATOR
# ============================================================================

class CVSSCalculatorTool(BaseTool):
    name: str = "cvss_calculator"
    description: str = """
    Calculate precise CVSS v3.1 base scores and vector strings for 
    vulnerabilities. Determines Attack Vector, Complexity, Privileges, 
    User Interaction, Scope, and Impact metrics based on vulnerability type 
    and validation status. Returns structured severity data with full 
    justification.
    """
    args_schema: Type[BaseModel] = CVSSInput

    # CVSS v3.1 metric values
    METRIC_VALUES: ClassVar[Dict[str, Dict[str, float]]] = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "PR_SC": {"N": 0.85, "L": 0.68, "H": 0.50},
        "UI": {"N": 0.85, "R": 0.62},
        "S": {"U": 6.42, "C": 7.52},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0}
    }

    def _run(self, finding: Dict[str, Any]) -> str:
        try:
            vuln_type = finding.get("type", "").lower()
            subtype = finding.get("subtype", "").lower()
            validated = finding.get("validated", False)
            
            # Initialize metrics
            metrics = {
                "AV": "N",
                "AC": "L",
                "PR": "N",
                "UI": "N",
                "S": "U",
                "C": "N",
                "I": "N",
                "A": "N"
            }
            
            # Apply vulnerability-type-specific metrics
            metrics = self._apply_vuln_type_metrics(metrics, vuln_type, subtype, finding)
            
            # Adjust for validation status
            if not validated:
                metrics["AC"] = "H"
            
            # Adjust for authentication requirements
            if finding.get("requires_auth") or finding.get("authenticated"):
                metrics["PR"] = "L"
            
            # Adjust for user interaction requirements
            if "xss" in vuln_type or "csrf" in vuln_type:
                metrics["UI"] = "R"
            
            # Calculate scores
            base_score, impact_score, exploitability_score = self._calculate_cvss(metrics)
            
            # Determine severity rating
            severity = self._severity_rating(base_score)
            
            # Generate vector string
            vector = self._build_vector(metrics)
            
            # Business impact assessment
            business_impact = self._assess_business_impact(finding, metrics, base_score)
            
            # EPSS lookup if CVE present
            epss_data = self._get_epss_data(finding.get("cve_id"))
            
            return json.dumps({
                "tool": "cvss_calculator",
                "vuln_id": finding.get("id", "unknown"),
                "vuln_type": vuln_type,
                "cvss_version": "3.1",
                "base_score": round(base_score, 1),
                "impact_score": round(impact_score, 1),
                "exploitability_score": round(exploitability_score, 1),
                "cvss_vector": vector,
                "severity_rating": severity,
                "metrics": metrics,
                "validated": validated,
                "confidence": "High" if validated else "Medium",
                "business_impact": business_impact,
                "epss": epss_data,
                "justification": self._build_justification(metrics, base_score, finding),
                "remediation_priority": self._priority(base_score, epss_data.get("score", 0) or 0)
            }, indent=2)
            
        except Exception as e:
            return json.dumps({
                "tool": "cvss_calculator",
                "error": f"CVSS calculation failed: {str(e)}",
                "vuln_id": finding.get("id", "unknown"),
                "base_score": 0.0,
                "severity_rating": "Unknown"
            }, indent=2)
    
    def _apply_vuln_type_metrics(self, metrics: Dict[str, str], vuln_type: str,
                                   subtype: str, finding: Dict[str, Any]) -> Dict[str, str]:
        """Apply base metrics based on vulnerability type."""
        
        if "xss" in vuln_type:
            metrics.update({
                "PR": "N",
                "UI": "R",
                "S": "C",
                "C": "L",
                "I": "L",
                "A": "N"
            })
            if "stored" in subtype or "persistent" in subtype:
                metrics.update({"C": "H", "I": "H"})
            if finding.get("cookies_accessible") or finding.get("session_hijack_risk") == "CRITICAL":
                metrics.update({"C": "H", "I": "H"})
        
        elif "sql" in vuln_type:
            metrics.update({
                "PR": "N",
                "S": "C",
                "C": "H",
                "I": "H",
                "A": "H"
            })
            if "error" in subtype:
                metrics["AC"] = "L"
            elif "blind" in subtype:
                metrics["AC"] = "H"
        
        elif any(x in vuln_type for x in ["rce", "command", "code"]):
            metrics.update({
                "PR": "N",
                "S": "C",
                "C": "H",
                "I": "H",
                "A": "H"
            })
        
        elif "ssrf" in vuln_type:
            metrics.update({
                "PR": "N",
                "S": "U",
                "C": "H",
                "I": "L",
                "A": "N"
            })
        
        elif "lfi" in vuln_type or "path" in vuln_type:
            metrics.update({
                "PR": "N",
                "S": "U",
                "C": "H",
                "I": "N",
                "A": "N"
            })
        
        elif "cve" in vuln_type:
            severity = finding.get("severity", "medium").lower()
            if severity == "critical":
                metrics.update({"C": "H", "I": "H", "A": "H"})
            elif severity == "high":
                metrics.update({"C": "H", "I": "H", "A": "L"})
            elif severity == "medium":
                metrics.update({"C": "L", "I": "L", "A": "N"})
        
        elif "misconfig" in vuln_type:
            metrics.update({
                "PR": "N",
                "S": "U",
                "C": "L",
                "I": "N",
                "A": "N"
            })
        
        return metrics
    
    def _calculate_cvss(self, metrics: Dict[str, str]) -> tuple:
        """Calculate CVSS v3.1 base score."""
        
        iss = 1 - (
            (1 - self.METRIC_VALUES["C"][metrics["C"]]) *
            (1 - self.METRIC_VALUES["I"][metrics["I"]]) *
            (1 - self.METRIC_VALUES["A"][metrics["A"]])
        )
        
        if metrics["S"] == "C":
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        else:
            impact = 6.42 * iss
        
        pr_values = self.METRIC_VALUES["PR_SC"] if metrics["S"] == "C" else self.METRIC_VALUES["PR"]
        
        exploitability = (
            8.22 *
            self.METRIC_VALUES["AV"][metrics["AV"]] *
            self.METRIC_VALUES["AC"][metrics["AC"]] *
            pr_values[metrics["PR"]] *
            self.METRIC_VALUES["UI"][metrics["UI"]]
        )
        
        if impact <= 0:
            base_score = 0.0
        else:
            if metrics["S"] == "C":
                base_score = min(1.08 * (impact + exploitability), 10)
            else:
                base_score = min(impact + exploitability, 10)
        
        return base_score, impact, exploitability
    
    def _severity_rating(self, score: float) -> str:
        """Map CVSS score to severity rating."""
        if score == 0.0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"
    
    def _build_vector(self, metrics: Dict[str, str]) -> str:
        """Build CVSS v3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}"
            f"/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
        )
    
    def _assess_business_impact(self, finding: Dict[str, Any], 
                                  metrics: Dict[str, str], score: float) -> Dict[str, Any]:
        """Assess business impact beyond technical CVSS."""
        
        impact = {
            "data_at_risk": [],
            "regulatory_impact": [],
            "reputational_risk": "Low",
            "financial_risk": "Low",
            "operational_impact": "Low"
        }
        
        if metrics["C"] == "H":
            impact["data_at_risk"].extend(["PII", "Credentials", "Session Tokens"])
            impact["reputational_risk"] = "Critical"
            impact["financial_risk"] = "High"
        
        if metrics["I"] == "H":
            impact["data_at_risk"].append("Data Integrity")
            impact["operational_impact"] = "High"
        
        if metrics["A"] == "H":
            impact["operational_impact"] = "Critical"
        
        finding_str = str(finding).lower()
        if "session" in finding_str or "cookie" in finding_str:
            impact["regulatory_impact"].extend(["GDPR", "CCPA"])
        
        if "payment" in finding_str or "card" in finding_str:
            impact["regulatory_impact"].append("PCI-DSS")
        
        if "health" in finding_str or "medical" in finding_str:
            impact["regulatory_impact"].append("HIPAA")
        
        if score >= 9.0:
            impact["reputational_risk"] = "Critical"
            impact["financial_risk"] = "Critical"
        elif score >= 7.0:
            impact["reputational_risk"] = "High"
            impact["financial_risk"] = "High"
        
        return impact
    
    def _get_epss_data(self, cve_id: Any) -> Dict[str, Any]:
        """Query EPSS API for exploitation probability."""
        if not cve_id:
            return {"score": None, "percentile": None, "queried": False}
        
        if isinstance(cve_id, list):
            cve_id = cve_id[0] if cve_id else None
        if not cve_id:
            return {"score": None, "percentile": None, "queried": False}
        
        try:
            response = requests.get(
                Config.EPSS_API_URL,
                params={"cve": cve_id},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("data"):
                    entry = data["data"][0]
                    return {
                        "score": float(entry.get("epss", 0)),
                        "percentile": float(entry.get("percentile", 0)),
                        "date": entry.get("date", ""),
                        "queried": True
                    }
        except Exception:
            pass
        
        return {"score": None, "percentile": None, "queried": False, "error": "EPSS query failed"}
    
    def _build_justification(self, metrics: Dict[str, str], score: float,
                              finding: Dict[str, Any]) -> str:
        """Build human-readable justification for the score."""
        parts = [
            f"Base Score {score:.1f} calculated from:",
            f"- Attack Vector ({metrics['AV']}): {'Network-based' if metrics['AV'] == 'N' else 'Requires local access'}",
            f"- Attack Complexity ({metrics['AC']}): {'Low - trivial' if metrics['AC'] == 'L' else 'High - advanced'}",
            f"- Privileges ({metrics['PR']}): {'None' if metrics['PR'] == 'N' else 'Low' if metrics['PR'] == 'L' else 'High'}",
            f"- User Interaction ({metrics['UI']}): {'None' if metrics['UI'] == 'N' else 'Required'}",
            f"- Scope ({metrics['S']}): {'Unchanged' if metrics['S'] == 'U' else 'Changed'}",
            f"- Confidentiality ({metrics['C']}): {'None' if metrics['C'] == 'N' else 'Low' if metrics['C'] == 'L' else 'High'}",
            f"- Integrity ({metrics['I']}): {'None' if metrics['I'] == 'N' else 'Low' if metrics['I'] == 'L' else 'High'}",
            f"- Availability ({metrics['A']}): {'None' if metrics['A'] == 'N' else 'Low' if metrics['A'] == 'L' else 'High'}"
        ]
        
        if finding.get("validated"):
            parts.append("- Finding validated with PoC")
        else:
            parts.append("- Finding not validated; score may be adjusted")
        
        return " | ".join(parts)
    
    def _priority(self, cvss_score: float, epss_score: float) -> str:
        """Determine remediation priority combining CVSS and EPSS."""
        if cvss_score >= 9.0:
            return "P1-Critical"
        elif cvss_score >= 7.0 and epss_score and epss_score > 0.5:
            return "P1-Critical"
        elif cvss_score >= 7.0:
            return "P2-High"
        elif cvss_score >= 4.0 and epss_score and epss_score > 0.1:
            return "P2-High"
        elif cvss_score >= 4.0:
            return "P3-Medium"
        else:
            return "P4-Low"
