"""
TRINETRA — Architecture Interfaces & Base Classes
Foundational contracts for intelligence layers, providers, and response engines.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from app.models import Decision, Severity


# ==================================================
# Data Transfer Contracts
# ==================================================

class AnalysisContext(BaseModel):
    """Context object carrying parsed email information through intelligence layers."""
    email_id: str
    message_id: str
    sender: str
    sender_domain: str
    recipient: str
    subject: str
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    headers: Dict[str, Any] = {}
    extracted_urls: List[str] = []


class LayerSignal(BaseModel):
    """Normalized signal produced by an individual intelligence layer."""
    layer: str
    signal_type: str
    score: float  # 0.0 to 1.0
    description: str
    metadata: Dict[str, Any] = {}


class LayerResult(BaseModel):
    """Result returned by an intelligence layer analyzer."""
    layer: str
    layer_risk_score: float  # 0.0 to 1.0
    signals: List[LayerSignal] = []
    metadata: Dict[str, Any] = {}


class RiskEngineOutput(BaseModel):
    """Consolidated assessment output from the Multi-Signal Risk Engine."""
    final_risk_score: float
    severity: Severity
    decision: Decision
    confidence: float
    layer_scores: Dict[str, float]
    all_signals: List[LayerSignal]
    evidence: Dict[str, Any]
    recommended_action: str


# ==================================================
# Analyzer Interfaces (Detection Layers 1-3)
# ==================================================

class ContentAnalyzer(ABC):
    """Layer 1: Analyzes textual & semantic content for phishing indicators."""

    @abstractmethod
    async def analyze_content(self, context: AnalysisContext) -> LayerResult:
        """Evaluate text, headers, and semantic structure."""
        pass


class URLAnalyzer(ABC):
    """Layer 2: Evaluates URL and domain characteristics, reputation, and structure."""

    @abstractmethod
    async def analyze_urls(self, context: AnalysisContext) -> LayerResult:
        """Inspect and score extracted URLs and destination domains."""
        pass


class IdentityAnalyzer(ABC):
    """Layer 3: Verifies sender identity, SPF/DKIM/DMARC, spoofing, and lookalike brands."""

    @abstractmethod
    async def analyze_identity(self, context: AnalysisContext) -> LayerResult:
        """Evaluate sender legitimacy and spoofing vectors."""
        pass


# ==================================================
# Threat Intel Provider Interface (Layer 4)
# ==================================================

class ThreatIntelProvider(ABC):
    """Layer 4: External or internal Threat Intelligence IOC lookups."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the threat intelligence provider (e.g., LocalDB, CERT-In, VT)."""
        pass

    @abstractmethod
    async def lookup_indicator(self, indicator_type: str, indicator_value: str) -> Optional[Dict[str, Any]]:
        """Look up reputation data for an indicator."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if provider is responsive/configured."""
        pass


# ==================================================
# Graph Engine Interface (Layer 5)
# ==================================================

class GraphEngine(ABC):
    """Layer 5: Graph analysis for relationships across senders, domains, and recipients."""

    @abstractmethod
    async def build_or_update_relationships(self, context: AnalysisContext) -> None:
        """Ingest entities and link relationships."""
        pass

    @abstractmethod
    async def compute_graph_risk(self, context: AnalysisContext) -> LayerResult:
        """Compute community, centrality, or anomaly risk across the identity graph."""
        pass


# ==================================================
# Central Risk Engine Interface (Layer 6)
# ==================================================

class RiskEngine(ABC):
    """Layer 6: Aggregates multiple intelligence layers into final score and decision."""

    @abstractmethod
    async def evaluate_risks(
        self,
        context: AnalysisContext,
        layer_results: Dict[str, LayerResult],
    ) -> RiskEngineOutput:
        """Compute weighted score and formulate decision (ALLOW/WARN/QUARANTINE)."""
        pass


# ==================================================
# Explainability Provider Interface (Layer 7)
# ==================================================

class ExplanationProvider(ABC):
    """Layer 7: Synthesizes evidence into human-readable SOC explanations."""

    @abstractmethod
    async def generate_explanation(
        self,
        risk_output: RiskEngineOutput,
        context: AnalysisContext,
    ) -> str:
        """Generate clear evidence-backed explanation without fabricating facts."""
        pass


# ==================================================
# Action Provider Interface
# ==================================================

class ActionProvider(ABC):
    """Applies decisions (quarantine, label, warning) to targeted email accounts."""

    @abstractmethod
    async def execute_action(self, email_id: str, decision: Decision) -> bool:
        """Execute decision action in accordance with security policy."""
        pass
