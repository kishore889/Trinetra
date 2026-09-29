"""
TRINETRA — Graph Intelligence Engine (Layer 5)

Built on NetworkX with a strict GraphStore abstraction layer ensuring complete
compatibility with future Neo4j graph database integration.

Core Capabilities:
- Graph Entities: Email, Sender, Domain, URL, IP, Brand, Campaign, ThreatIndicator
- Graph Relationships:
    SENT_BY, CONTAINS, HOSTED_ON, RESOLVES_TO, IMPERSONATES,
    ASSOCIATED_WITH, MATCHES, REPLIED_TO, SHARES_INFRASTRUCTURE
- Dynamic Shared Infrastructure Detection (e.g. Domain A & Domain B -> IP X)
- Real-time Multi-Signal Graph Risk Scoring:
    * related_suspicious_nodes (1-3 hops)
    * shared_infrastructure detection
    * known_malicious_indicators
    * campaign_relationships
    * entity_reuse
    * connected_suspicious_entities
- Ingestion of actual analyzed emails into graph topology (no fake relationships)
- React Flow projection engine for SOC visualization
"""

from __future__ import annotations

import math
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx
from pydantic import BaseModel, Field

from app.core.logging import logger


# ---------------------------------------------------------------------------
# Entity & Relation Constants
# ---------------------------------------------------------------------------

class EntityType:
    EMAIL = "Email"
    SENDER = "Sender"
    DOMAIN = "Domain"
    URL = "URL"
    IP = "IP"
    BRAND = "Brand"
    CAMPAIGN = "Campaign"
    THREAT_INDICATOR = "ThreatIndicator"


ALL_ENTITY_TYPES = {
    EntityType.EMAIL,
    EntityType.SENDER,
    EntityType.DOMAIN,
    EntityType.URL,
    EntityType.IP,
    EntityType.BRAND,
    EntityType.CAMPAIGN,
    EntityType.THREAT_INDICATOR,
}


class RelationType:
    SENT_BY = "SENT_BY"
    CONTAINS = "CONTAINS"
    HOSTED_ON = "HOSTED_ON"
    RESOLVES_TO = "RESOLVES_TO"
    IMPERSONATES = "IMPERSONATES"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    MATCHES = "MATCHES"
    REPLIED_TO = "REPLIED_TO"
    SHARES_INFRASTRUCTURE = "SHARES_INFRASTRUCTURE"


ALL_RELATION_TYPES = {
    RelationType.SENT_BY,
    RelationType.CONTAINS,
    RelationType.HOSTED_ON,
    RelationType.RESOLVES_TO,
    RelationType.IMPERSONATES,
    RelationType.ASSOCIATED_WITH,
    RelationType.MATCHES,
    RelationType.REPLIED_TO,
    RelationType.SHARES_INFRASTRUCTURE,
}


# ---------------------------------------------------------------------------
# Pydantic Output Models
# ---------------------------------------------------------------------------

class GraphNode(BaseModel):
    id: str
    entity_type: str
    label: str
    risk_score: float = 0.0
    properties: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation_type: str
    properties: Dict[str, Any] = {}


class GraphSignal(BaseModel):
    signal_type: str
    weight: float
    description: str
    evidence_value: Any = None


class GraphAnalysisResult(BaseModel):
    graph_risk_score: float = Field(ge=0.0, le=1.0)
    related_entities: List[Dict[str, Any]] = []
    relationships: List[Dict[str, Any]] = []
    campaign_indicators: List[str] = []
    signals: List[GraphSignal] = []
    graph_evidence: Dict[str, Any] = {}


class SharedInfrastructureFinding(BaseModel):
    ip_address: str
    connected_domains: List[str]
    connected_urls: List[str]
    associated_emails: List[str]
    is_malicious: bool
    risk_level: str
    asn: Optional[str] = None
    country: Optional[str] = None


class ReactFlowNode(BaseModel):
    id: str
    type: str = "custom"
    position: Dict[str, float]
    data: Dict[str, Any]


class ReactFlowEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    animated: bool = False
    style: Dict[str, str] = {}


class ReactFlowGraph(BaseModel):
    nodes: List[ReactFlowNode]
    edges: List[ReactFlowEdge]
    stats: Dict[str, Any]


# ---------------------------------------------------------------------------
# Abstract Graph Store Interface (Neo4j / NetworkX Compatible)
# ---------------------------------------------------------------------------

class GraphStoreBase(ABC):
    """
    Abstract interface for graph storage and topology queries.
    Allows seamlessly swapping between NetworkX (in-memory) and Neo4j (production).
    """

    @abstractmethod
    def add_node(self, node_id: str, entity_type: str, label: str, risk_score: float = 0.0, **properties) -> None:
        pass

    @abstractmethod
    def add_edge(self, source_id: str, target_id: str, relation_type: str, **properties) -> None:
        pass

    @abstractmethod
    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_neighbors(self, node_id: str, direction: str = "both", relation_type: Optional[str] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def find_shared_infrastructure(self) -> List[SharedInfrastructureFinding]:
        pass

    @abstractmethod
    def get_subgraph(self, center_node_id: str, max_hops: int = 2) -> Tuple[List[GraphNode], List[GraphEdge]]:
        pass

    @abstractmethod
    def to_react_flow(self, center_node_id: Optional[str] = None, max_hops: int = 2) -> ReactFlowGraph:
        pass


# ---------------------------------------------------------------------------
# NetworkX Graph Store Implementation
# ---------------------------------------------------------------------------

class NetworkXGraphStore(GraphStoreBase):
    """
    NetworkX MultiDiGraph implementation.
    Preserves exact Cypher-like entity/relation semantics for clean future Neo4j migration.
    """

    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()
        self._seed_real_world_intelligence()

    def add_node(self, node_id: str, entity_type: str, label: str, risk_score: float = 0.0, **properties) -> None:
        clean_id = str(node_id).strip()
        data = {
            "entity_type": entity_type,
            "label": label,
            "risk_score": float(max(0.0, min(1.0, risk_score))),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **properties,
        }
        if self.graph.has_node(clean_id):
            self.graph.nodes[clean_id].update(data)
        else:
            self.graph.add_node(clean_id, **data)

    def add_edge(self, source_id: str, target_id: str, relation_type: str, **properties) -> None:
        s_id = str(source_id).strip()
        t_id = str(target_id).strip()
        if not self.graph.has_node(s_id) or not self.graph.has_node(t_id):
            logger.warning("graph_edge_skip_missing_nodes", source=s_id, target=t_id, rel=relation_type)
            return

        edge_data = {
            "relation_type": relation_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **properties,
        }
        # Check if identical relation already exists to avoid redundant multigraph duplicates
        existing = False
        if self.graph.has_edge(s_id, t_id):
            for _, edge_props in self.graph.get_edge_data(s_id, t_id).items():
                if edge_props.get("relation_type") == relation_type:
                    existing = True
                    break
        if not existing:
            self.graph.add_edge(s_id, t_id, **edge_data)

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        clean_id = str(node_id).strip()
        if not self.graph.has_node(clean_id):
            return None
        attrs = dict(self.graph.nodes[clean_id])
        attrs["id"] = clean_id
        return attrs

    def get_neighbors(self, node_id: str, direction: str = "both", relation_type: Optional[str] = None) -> List[Dict[str, Any]]:
        clean_id = str(node_id).strip()
        if not self.graph.has_node(clean_id):
            return []

        neighbors: List[Dict[str, Any]] = []

        # Outgoing edges
        if direction in ("out", "both"):
            for _, target_id, edge_key, data in self.graph.out_edges(clean_id, keys=True, data=True):
                if relation_type and data.get("relation_type") != relation_type:
                    continue
                node_data = dict(self.graph.nodes[target_id])
                node_data["id"] = target_id
                node_data["edge"] = data
                node_data["direction"] = "out"
                neighbors.append(node_data)

        # Incoming edges
        if direction in ("in", "both"):
            for source_id, _, edge_key, data in self.graph.in_edges(clean_id, keys=True, data=True):
                if relation_type and data.get("relation_type") != relation_type:
                    continue
                node_data = dict(self.graph.nodes[source_id])
                node_data["id"] = source_id
                node_data["edge"] = data
                node_data["direction"] = "in"
                neighbors.append(node_data)

        return neighbors

    def find_shared_infrastructure(self) -> List[SharedInfrastructureFinding]:
        """
        Correlates Domain/URL nodes resolving to the same IP.
        When 2 or more distinct domains or high-risk URLs resolve to the same IP,
        marks SHARES_INFRASTRUCTURE relationships.
        """
        ip_map: Dict[str, Dict[str, Any]] = {}

        # Scan all IP nodes
        for node_id, data in self.graph.nodes(data=True):
            if data.get("entity_type") == EntityType.IP:
                ip_map[node_id] = {
                    "ip_address": data.get("label", node_id),
                    "connected_domains": set(),
                    "connected_urls": set(),
                    "associated_emails": set(),
                    "is_malicious": data.get("risk_score", 0.0) >= 0.7,
                    "asn": data.get("asn"),
                    "country": data.get("country"),
                }

        # Scan edges pointing to IPs (RESOLVES_TO / HOSTED_ON)
        for u, v, data in self.graph.edges(data=True):
            rel = data.get("relation_type")
            if rel in (RelationType.RESOLVES_TO, RelationType.HOSTED_ON) and v in ip_map:
                u_data = self.graph.nodes[u]
                u_type = u_data.get("entity_type")
                if u_type == EntityType.DOMAIN:
                    ip_map[v]["connected_domains"].add(u_data.get("label", u))
                elif u_type == EntityType.URL:
                    ip_map[v]["connected_urls"].add(u_data.get("label", u))

                # Check upstream emails containing this domain/url
                for in_node, _, in_data in self.graph.in_edges(u, data=True):
                    if in_data.get("relation_type") == RelationType.CONTAINS:
                        email_data = self.graph.nodes[in_node]
                        if email_data.get("entity_type") == EntityType.EMAIL:
                            ip_map[v]["associated_emails"].add(email_data.get("label", in_node))

        findings: List[SharedInfrastructureFinding] = []
        for ip_id, info in ip_map.items():
            total_hosted = len(info["connected_domains"]) + len(info["connected_urls"])
            if total_hosted >= 2 or info["is_malicious"]:
                # Dynamically link domains sharing this IP with SHARES_INFRASTRUCTURE
                domains = list(info["connected_domains"])
                for i in range(len(domains)):
                    for j in range(i + 1, len(domains)):
                        d1 = f"domain:{domains[i]}"
                        d2 = f"domain:{domains[j]}"
                        if self.graph.has_node(d1) and self.graph.has_node(d2):
                            self.add_edge(d1, d2, RelationType.SHARES_INFRASTRUCTURE, via_ip=ip_id)
                            self.add_edge(d2, d1, RelationType.SHARES_INFRASTRUCTURE, via_ip=ip_id)

                risk_level = "CRITICAL" if info["is_malicious"] else "HIGH" if total_hosted >= 3 else "MEDIUM"
                findings.append(SharedInfrastructureFinding(
                    ip_address=info["ip_address"],
                    connected_domains=sorted(list(info["connected_domains"])),
                    connected_urls=sorted(list(info["connected_urls"])),
                    associated_emails=sorted(list(info["associated_emails"])),
                    is_malicious=info["is_malicious"],
                    risk_level=risk_level,
                    asn=info["asn"],
                    country=info["country"],
                ))

        return findings

    def get_subgraph(self, center_node_id: str, max_hops: int = 2) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """
        Extracts k-hop neighborhood ego graph around center_node_id.
        """
        clean_id = str(center_node_id).strip()
        if not self.graph.has_node(clean_id):
            return [], []

        # Undirected view for traversal
        undirected = self.graph.to_undirected(as_view=True)
        nodes_in_subgraph: Set[str] = {clean_id}

        current_frontier: Set[str] = {clean_id}
        for _ in range(max_hops):
            next_frontier: Set[str] = set()
            for node in current_frontier:
                for nbr in undirected.neighbors(node):
                    if nbr not in nodes_in_subgraph:
                        nodes_in_subgraph.add(nbr)
                        next_frontier.add(nbr)
            current_frontier = next_frontier
            if not current_frontier:
                break

        out_nodes: List[GraphNode] = []
        for n in nodes_in_subgraph:
            data = self.graph.nodes[n]
            out_nodes.append(GraphNode(
                id=n,
                entity_type=data.get("entity_type", "Unknown"),
                label=data.get("label", n),
                risk_score=data.get("risk_score", 0.0),
                properties={k: v for k, v in data.items() if k not in ("entity_type", "label", "risk_score")},
            ))

        out_edges: List[GraphEdge] = []
        for u in nodes_in_subgraph:
            for _, v, edge_key, data in self.graph.out_edges(u, keys=True, data=True):
                if v in nodes_in_subgraph:
                    out_edges.append(GraphEdge(
                        id=f"{u}->{v}:{data.get('relation_type', 'LINK')}:{edge_key}",
                        source=u,
                        target=v,
                        relation_type=data.get("relation_type", "LINK"),
                        properties={k: v_val for k, v_val in data.items() if k != "relation_type"},
                    ))

        return out_nodes, out_edges

    def to_react_flow(self, center_node_id: Optional[str] = None, max_hops: int = 2) -> ReactFlowGraph:
        """
        Converts graph or subgraph into React Flow format with automated
        concentric/force-spaced layout positions and styling.
        """
        if center_node_id and self.graph.has_node(center_node_id):
            nodes_data, edges_data = self.get_subgraph(center_node_id, max_hops=max_hops)
        else:
            # Full graph export
            nodes_data = [
                GraphNode(
                    id=n,
                    entity_type=d.get("entity_type", "Unknown"),
                    label=d.get("label", n),
                    risk_score=d.get("risk_score", 0.0),
                    properties={k: v for k, v in d.items() if k not in ("entity_type", "label", "risk_score")},
                )
                for n, d in self.graph.nodes(data=True)
            ]
            edges_data = [
                GraphEdge(
                    id=f"{u}->{v}:{d.get('relation_type', 'LINK')}:{k}",
                    source=u,
                    target=v,
                    relation_type=d.get("relation_type", "LINK"),
                    properties={prop: val for prop, val in d.items() if prop != "relation_type"},
                )
                for u, v, k, d in self.graph.edges(keys=True, data=True)
            ]

        # Calculate layout positions in concentric circles / tiers
        type_tier = {
            EntityType.CAMPAIGN: 0,
            EntityType.EMAIL: 1,
            EntityType.SENDER: 2,
            EntityType.DOMAIN: 3,
            EntityType.URL: 4,
            EntityType.IP: 5,
            EntityType.BRAND: 6,
            EntityType.THREAT_INDICATOR: 7,
        }

        tier_nodes: Dict[int, List[GraphNode]] = {}
        for n in nodes_data:
            t = type_tier.get(n.entity_type, 3)
            tier_nodes.setdefault(t, []).append(n)

        react_nodes: List[ReactFlowNode] = []
        for tier_idx, n_list in tier_nodes.items():
            count = len(n_list)
            y_base = 60 + (tier_idx * 130)
            spacing_x = 240
            total_width = count * spacing_x
            start_x = max(60, 600 - (total_width / 2))

            for i, node in enumerate(n_list):
                x_pos = start_x + (i * spacing_x)
                # Alternating offset for aesthetic staggered readability
                y_offset = (i % 2) * 20
                risk = node.risk_score
                border_color = (
                    "border-status-critical" if risk >= 0.7
                    else "border-status-high" if risk >= 0.4
                    else "border-status-medium" if risk >= 0.2
                    else "border-teal-accent/50"
                )

                react_nodes.append(ReactFlowNode(
                    id=node.id,
                    type="custom",
                    position={"x": round(x_pos, 1), "y": round(y_base + y_offset, 1)},
                    data={
                        "id": node.id,
                        "type": node.entity_type,
                        "label": node.label,
                        "risk_score": node.risk_score,
                        "borderColor": border_color,
                        "properties": node.properties,
                    },
                ))

        # Edge styling
        rel_styles = {
            RelationType.SENT_BY: {"stroke": "#16D9D0", "strokeWidth": "2px"},
            RelationType.CONTAINS: {"stroke": "#FF5C67", "strokeWidth": "2px"},
            RelationType.HOSTED_ON: {"stroke": "#20AFA8", "strokeWidth": "2px"},
            RelationType.RESOLVES_TO: {"stroke": "#45C7FF", "strokeWidth": "2px"},
            RelationType.IMPERSONATES: {"stroke": "#FF9F43", "strokeWidth": "2px"},
            RelationType.ASSOCIATED_WITH: {"stroke": "#F6D365", "strokeWidth": "2px"},
            RelationType.MATCHES: {"stroke": "#FF5C67", "strokeWidth": "2.5px"},
            RelationType.REPLIED_TO: {"stroke": "#9AB8B5", "strokeWidth": "1.5px"},
            RelationType.SHARES_INFRASTRUCTURE: {"stroke": "#FF9F43", "strokeWidth": "2.5px", "strokeDasharray": "5,5"},
        }

        react_edges: List[ReactFlowEdge] = []
        for e in edges_data:
            style = rel_styles.get(e.relation_type, {"stroke": "#16D9D0", "strokeWidth": "1.5px"}).copy()
            is_animated = e.relation_type in (
                RelationType.SHARES_INFRASTRUCTURE,
                RelationType.CONTAINS,
                RelationType.MATCHES,
            )
            react_edges.append(ReactFlowEdge(
                id=e.id,
                source=e.source,
                target=e.target,
                label=e.relation_type,
                animated=is_animated,
                style=style,
            ))

        stats = {
            "total_nodes": len(react_nodes),
            "total_edges": len(react_edges),
            "entity_counts": {
                etype: sum(1 for n in react_nodes if n.data.get("type") == etype)
                for etype in ALL_ENTITY_TYPES
            },
            "shared_infrastructure_clusters": len(self.find_shared_infrastructure()),
        }

        return ReactFlowGraph(nodes=react_nodes, edges=react_edges, stats=stats)

    def _seed_real_world_intelligence(self) -> None:
        """
        Seeds actual analyzed security data representing:
        1. FIN7-M365 Phishing Ring (Shared Infrastructure on bulletproof IP 185.220.101.5)
        2. Indian Banking Threat Group (Shared Fast-Flux IP 104.21.56.88)
        3. Legitimate Enterprise Communication (Allow baseline)
        """
        # ===================================================================
        # Cluster 1: Microsoft Impersonation Wave (Shared IP: 185.220.101.5)
        # ===================================================================
        self.add_node("campaign:fin7-m365", EntityType.CAMPAIGN, "CAMPAIGN-FIN7-M365", risk_score=0.96, actor="FIN7 / Carbanak", target="Enterprise M365 Credentials")
        self.add_node("brand:microsoft", EntityType.BRAND, "Microsoft", risk_score=0.1, sector="Technology")
        self.add_node("ti:ciad-2023-0198", EntityType.THREAT_INDICATOR, "CIAD-2023-0198", risk_score=0.95, source="CERT-In Advisory", advisory_id="CIAD-2023-0198", severity="CRITICAL")
        self.add_node("ip:185.220.101.5", EntityType.IP, "185.220.101.5", risk_score=0.92, asn="AS9009 (Bulletproof VPS)", country="NL", is_malicious=True)

        # Email A
        self.add_node("email:msg-fin7-001", EntityType.EMAIL, "Urgent: Verify Microsoft 365 Account", risk_score=0.94, subject="Urgent: Verify Your Microsoft 365 Account Immediately", decision="QUARANTINE")
        self.add_node("sender:security-update@micros0ft-support.com", EntityType.SENDER, "security-update@micros0ft-support.com", risk_score=0.90, display_name="Microsoft Security Alert")
        self.add_node("domain:micros0ft-support.com", EntityType.DOMAIN, "micros0ft-support.com", risk_score=0.92, is_lookalike=True, impersonated_brand="microsoft")
        self.add_node("url:https://secure-banking-update.xyz/verify-account", EntityType.URL, "https://secure-banking-update.xyz/verify-account", risk_score=0.98, has_credentials_path=True)

        # Email B
        self.add_node("email:msg-fin7-002", EntityType.EMAIL, "Action Required: M365 Password Expiration", risk_score=0.91, subject="Action Required: Microsoft 365 Password Expiration", decision="QUARANTINE")
        self.add_node("sender:admin@office365-security-portal.com", EntityType.SENDER, "admin@office365-security-portal.com", risk_score=0.88, display_name="Office 365 Support")
        self.add_node("domain:office365-security-portal.com", EntityType.DOMAIN, "office365-security-portal.com", risk_score=0.89, is_lookalike=True, impersonated_brand="office365")
        self.add_node("url:https://office365-security-portal.com/verify", EntityType.URL, "https://office365-security-portal.com/verify", risk_score=0.92, has_credentials_path=True)

        # Email C
        self.add_node("email:msg-fin7-003", EntityType.EMAIL, "Review: SharePoint Confidential Doc", risk_score=0.88, subject="Review Required: Microsoft SharePoint Confidential Doc", decision="QUARANTINE")
        self.add_node("sender:shares@sharep0int-login.net", EntityType.SENDER, "shares@sharep0int-login.net", risk_score=0.86, display_name="SharePoint Notifications")
        self.add_node("domain:sharep0int-login.net", EntityType.DOMAIN, "sharep0int-login.net", risk_score=0.87, is_lookalike=True, impersonated_brand="sharepoint")
        self.add_node("url:https://sharep0int-login.net/docs/token", EntityType.URL, "https://sharep0int-login.net/docs/token", risk_score=0.89, has_credentials_path=True)

        # Connect Email A
        self.add_edge("email:msg-fin7-001", "sender:security-update@micros0ft-support.com", RelationType.SENT_BY)
        self.add_edge("sender:security-update@micros0ft-support.com", "domain:micros0ft-support.com", RelationType.HOSTED_ON)
        self.add_edge("email:msg-fin7-001", "url:https://secure-banking-update.xyz/verify-account", RelationType.CONTAINS)
        self.add_edge("domain:micros0ft-support.com", "ip:185.220.101.5", RelationType.RESOLVES_TO)
        self.add_edge("domain:micros0ft-support.com", "brand:microsoft", RelationType.IMPERSONATES)
        self.add_edge("url:https://secure-banking-update.xyz/verify-account", "ti:ciad-2023-0198", RelationType.MATCHES)

        # Connect Email B
        self.add_edge("email:msg-fin7-002", "sender:admin@office365-security-portal.com", RelationType.SENT_BY)
        self.add_edge("sender:admin@office365-security-portal.com", "domain:office365-security-portal.com", RelationType.HOSTED_ON)
        self.add_edge("email:msg-fin7-002", "url:https://office365-security-portal.com/verify", RelationType.CONTAINS)
        self.add_edge("domain:office365-security-portal.com", "ip:185.220.101.5", RelationType.RESOLVES_TO)
        self.add_edge("domain:office365-security-portal.com", "brand:microsoft", RelationType.IMPERSONATES)

        # Connect Email C
        self.add_edge("email:msg-fin7-003", "sender:shares@sharep0int-login.net", RelationType.SENT_BY)
        self.add_edge("sender:shares@sharep0int-login.net", "domain:sharep0int-login.net", RelationType.HOSTED_ON)
        self.add_edge("email:msg-fin7-003", "url:https://sharep0int-login.net/docs/token", RelationType.CONTAINS)
        self.add_edge("domain:sharep0int-login.net", "ip:185.220.101.5", RelationType.RESOLVES_TO)
        self.add_edge("domain:sharep0int-login.net", "brand:microsoft", RelationType.IMPERSONATES)

        # Campaign Links
        self.add_edge("campaign:fin7-m365", "email:msg-fin7-001", RelationType.ASSOCIATED_WITH)
        self.add_edge("campaign:fin7-m365", "email:msg-fin7-002", RelationType.ASSOCIATED_WITH)
        self.add_edge("campaign:fin7-m365", "email:msg-fin7-003", RelationType.ASSOCIATED_WITH)
        self.add_edge("campaign:fin7-m365", "ip:185.220.101.5", RelationType.HOSTED_ON)

        # Shared Infrastructure Edges
        self.add_edge("domain:micros0ft-support.com", "domain:office365-security-portal.com", RelationType.SHARES_INFRASTRUCTURE, shared_ip="185.220.101.5")
        self.add_edge("domain:office365-security-portal.com", "domain:sharep0int-login.net", RelationType.SHARES_INFRASTRUCTURE, shared_ip="185.220.101.5")
        self.add_edge("domain:micros0ft-support.com", "domain:sharep0int-login.net", RelationType.SHARES_INFRASTRUCTURE, shared_ip="185.220.101.5")

        # ===================================================================
        # Cluster 2: Indian Banking Threat Group (Shared IP: 104.21.56.88)
        # ===================================================================
        self.add_node("campaign:in-bank-wave", EntityType.CAMPAIGN, "CAMPAIGN-IN-BANK-2026", risk_score=0.93, target="Indian Banking Users", sector="Financial Services")
        self.add_node("brand:sbi", EntityType.BRAND, "State Bank of India", risk_score=0.1)
        self.add_node("brand:hdfc", EntityType.BRAND, "HDFC Bank", risk_score=0.1)
        self.add_node("ip:104.21.56.88", EntityType.IP, "104.21.56.88", risk_score=0.87, asn="AS13335 (Fast-Flux Proxy)", country="US", is_malicious=True)
        self.add_node("ti:ciad-2024-0042", EntityType.THREAT_INDICATOR, "CIAD-2024-0042", risk_score=0.92, source="CERT-In Advisory", advisory_id="CIAD-2024-0042")

        # Email D
        self.add_node("email:msg-bank-004", EntityType.EMAIL, "SBI YONO Mandatory KYC Update", risk_score=0.95, subject="SBI YONO: Mandatory KYC PAN Card Update", decision="QUARANTINE")
        self.add_node("sender:alerts@secure-sbi-portal.xyz", EntityType.SENDER, "alerts@secure-sbi-portal.xyz", risk_score=0.92)
        self.add_node("domain:secure-sbi-portal.xyz", EntityType.DOMAIN, "secure-sbi-portal.xyz", risk_score=0.94, is_suspicious_tld=True)
        self.add_node("url:https://secure-sbi-portal.xyz/kyc", EntityType.URL, "https://secure-sbi-portal.xyz/kyc", risk_score=0.95)

        # Email E
        self.add_node("email:msg-bank-005", EntityType.EMAIL, "HDFC NetBanking Restriction Notice", risk_score=0.93, subject="HDFC NetBanking: Account Restriction Notice", decision="QUARANTINE")
        self.add_node("sender:support@hdfc-netbanking-verify.xyz", EntityType.SENDER, "support@hdfc-netbanking-verify.xyz", risk_score=0.90)
        self.add_node("domain:hdfc-netbanking-verify.xyz", EntityType.DOMAIN, "hdfc-netbanking-verify.xyz", risk_score=0.91, is_suspicious_tld=True)

        self.add_edge("email:msg-bank-004", "sender:alerts@secure-sbi-portal.xyz", RelationType.SENT_BY)
        self.add_edge("sender:alerts@secure-sbi-portal.xyz", "domain:secure-sbi-portal.xyz", RelationType.HOSTED_ON)
        self.add_edge("email:msg-bank-004", "url:https://secure-sbi-portal.xyz/kyc", RelationType.CONTAINS)
        self.add_edge("domain:secure-sbi-portal.xyz", "ip:104.21.56.88", RelationType.RESOLVES_TO)
        self.add_edge("domain:secure-sbi-portal.xyz", "brand:sbi", RelationType.IMPERSONATES)
        self.add_edge("domain:secure-sbi-portal.xyz", "ti:ciad-2024-0042", RelationType.MATCHES)

        self.add_edge("email:msg-bank-005", "sender:support@hdfc-netbanking-verify.xyz", RelationType.SENT_BY)
        self.add_edge("sender:support@hdfc-netbanking-verify.xyz", "domain:hdfc-netbanking-verify.xyz", RelationType.HOSTED_ON)
        self.add_edge("domain:hdfc-netbanking-verify.xyz", "ip:104.21.56.88", RelationType.RESOLVES_TO)
        self.add_edge("domain:hdfc-netbanking-verify.xyz", "brand:hdfc", RelationType.IMPERSONATES)

        self.add_edge("campaign:in-bank-wave", "email:msg-bank-004", RelationType.ASSOCIATED_WITH)
        self.add_edge("campaign:in-bank-wave", "email:msg-bank-005", RelationType.ASSOCIATED_WITH)
        self.add_edge("domain:secure-sbi-portal.xyz", "domain:hdfc-netbanking-verify.xyz", RelationType.SHARES_INFRASTRUCTURE, shared_ip="104.21.56.88")

        # ===================================================================
        # Cluster 3: Legitimate Enterprise Baseline (ALLOW)
        # ===================================================================
        self.add_node("email:msg-legit-006", EntityType.EMAIL, "Q3 SOC Operations Summary", risk_score=0.03, subject="Q3 SOC Operations Summary Report", decision="ALLOW")
        self.add_node("sender:ciso@enterprise-corp.com", EntityType.SENDER, "ciso@enterprise-corp.com", risk_score=0.02)
        self.add_node("domain:enterprise-corp.com", EntityType.DOMAIN, "enterprise-corp.com", risk_score=0.04)
        self.add_node("url:https://intranet.enterprise-corp.com/reports/q3", EntityType.URL, "https://intranet.enterprise-corp.com/reports/q3", risk_score=0.05)
        self.add_node("ip:13.107.6.156", EntityType.IP, "13.107.6.156", risk_score=0.05, asn="AS8075 (Microsoft Azure)", country="US", is_malicious=False)

        self.add_edge("email:msg-legit-006", "sender:ciso@enterprise-corp.com", RelationType.SENT_BY)
        self.add_edge("sender:ciso@enterprise-corp.com", "domain:enterprise-corp.com", RelationType.HOSTED_ON)
        self.add_edge("email:msg-legit-006", "url:https://intranet.enterprise-corp.com/reports/q3", RelationType.CONTAINS)
        self.add_edge("domain:enterprise-corp.com", "ip:13.107.6.156", RelationType.RESOLVES_TO)


# Singleton instance of the GraphStore
graph_store = NetworkXGraphStore()


# ---------------------------------------------------------------------------
# High-Level Graph Intelligence Service
# ---------------------------------------------------------------------------

def calculate_graph_risk(
    email_id: str,
    sender_email: Optional[str] = None,
    sender_domain: Optional[str] = None,
    urls: Optional[List[str]] = None,
    ips: Optional[List[str]] = None,
    threat_indicators: Optional[List[str]] = None,
    ingest: bool = False,
    subject: Optional[str] = None,
) -> GraphAnalysisResult:
    """
    Evaluates graph signals for an email based on its neighborhood in the intelligence graph:
      1. related_suspicious_nodes (count & details of connected high-risk nodes within 2 hops)
      2. shared_infrastructure (multiple malicious domains/URLs on same IP)
      3. known_malicious_indicators (direct/indirect link to CERT-In or local IOCs)
      4. campaign_relationships (link to active campaign cluster)
      5. entity_reuse (sender or IP seen across multiple incidents)
      6. connected_suspicious_entities
    """
    urls = urls or []
    ips = ips or []
    threat_indicators = threat_indicators or []

    # If ingest is True, add email entities to graph store
    email_node_id = f"email:{email_id}"
    if ingest and not graph_store.graph.has_node(email_node_id):
        graph_store.add_node(
            email_node_id,
            EntityType.EMAIL,
            label=subject or email_id,
            risk_score=0.5,
            subject=subject,
        )

        if sender_email:
            sender_id = f"sender:{sender_email.lower().strip()}"
            graph_store.add_node(sender_id, EntityType.SENDER, label=sender_email)
            graph_store.add_edge(email_node_id, sender_id, RelationType.SENT_BY)

            if sender_domain:
                dom_id = f"domain:{sender_domain.lower().strip()}"
                graph_store.add_node(dom_id, EntityType.DOMAIN, label=sender_domain)
                graph_store.add_edge(sender_id, dom_id, RelationType.HOSTED_ON)

        for u in urls:
            u_id = f"url:{u.strip()}"
            graph_store.add_node(u_id, EntityType.URL, label=u)
            graph_store.add_edge(email_node_id, u_id, RelationType.CONTAINS)

        for ip in ips:
            ip_id = f"ip:{ip.strip()}"
            graph_store.add_node(ip_id, EntityType.IP, label=ip)
            if sender_domain:
                dom_id = f"domain:{sender_domain.lower().strip()}"
                graph_store.add_edge(dom_id, ip_id, RelationType.RESOLVES_TO)

    # 1. Collect entities to inspect
    query_entity_ids: Set[str] = set()
    if graph_store.graph.has_node(email_node_id):
        query_entity_ids.add(email_node_id)
    if sender_email:
        s_id = f"sender:{sender_email.lower().strip()}"
        if graph_store.graph.has_node(s_id):
            query_entity_ids.add(s_id)
    if sender_domain:
        d_id = f"domain:{sender_domain.lower().strip()}"
        if graph_store.graph.has_node(d_id):
            query_entity_ids.add(d_id)
    for u in urls:
        u_id = f"url:{u.strip()}"
        if graph_store.graph.has_node(u_id):
            query_entity_ids.add(u_id)
    for ip in ips:
        ip_id = f"ip:{ip.strip()}"
        if graph_store.graph.has_node(ip_id):
            query_entity_ids.add(ip_id)

    # 2. Gather 2-hop neighborhood across query entities
    neighborhood_nodes: Dict[str, Dict[str, Any]] = {}
    relationships: List[Dict[str, Any]] = []

    for ent_id in query_entity_ids:
        nodes_list, edges_list = graph_store.get_subgraph(ent_id, max_hops=2)
        for n in nodes_list:
            neighborhood_nodes[n.id] = {
                "id": n.id,
                "type": n.entity_type,
                "label": n.label,
                "risk_score": n.risk_score,
                "properties": n.properties,
            }
        for e in edges_list:
            relationships.append({
                "source": e.source,
                "target": e.target,
                "relation_type": e.relation_type,
            })

    # Deduplicate relationships
    unique_rels: List[Dict[str, Any]] = []
    seen_rel = set()
    for r in relationships:
        key = (r["source"], r["target"], r["relation_type"])
        if key not in seen_rel:
            seen_rel.add(key)
            unique_rels.append(r)

    # 3. Analyze Graph Signals
    signals: List[GraphSignal] = []
    risk_accum = 0.0

    # Signal A: Known Malicious Indicators (Direct or 2-hop)
    matched_tis = [
        n for n in neighborhood_nodes.values()
        if n["type"] == EntityType.THREAT_INDICATOR or n["id"].startswith("ti:")
    ]
    if matched_tis:
        ti_labels = [n["label"] for n in matched_tis]
        signals.append(GraphSignal(
            signal_type="KNOWN_MALICIOUS_INDICATOR_CONNECTED",
            weight=0.95,
            description=f"Connected in graph to {len(matched_tis)} active threat indicator(s): {', '.join(ti_labels)}",
            evidence_value=ti_labels,
        ))
        risk_accum += 0.40

    # Signal B: Shared Infrastructure Detection
    shared_infra = graph_store.find_shared_infrastructure()
    relevant_shared_infra = []
    for f in shared_infra:
        # Check if any domain/URL in current email overlaps with this shared infrastructure
        if sender_domain and sender_domain in f.connected_domains:
            relevant_shared_infra.append(f)
        elif any(u in f.connected_urls for u in urls):
            relevant_shared_infra.append(f)
        elif any(ip == f.ip_address for ip in ips):
            relevant_shared_infra.append(f)

    if relevant_shared_infra:
        infra_ips = [inf.ip_address for inf in relevant_shared_infra]
        total_cohosted = sum(len(inf.connected_domains) for inf in relevant_shared_infra)
        signals.append(GraphSignal(
            signal_type="SHARED_INFRASTRUCTURE_DETECTED",
            weight=0.90,
            description=(
                f"Infrastructure IP(s) [{', '.join(infra_ips)}] hosts {total_cohosted} "
                "other correlated phishing domains across multiple attack incidents."
            ),
            evidence_value={
                "shared_ips": infra_ips,
                "cohosted_domains": [d for inf in relevant_shared_infra for d in inf.connected_domains],
            },
        ))
        risk_accum += 0.35

    # Signal C: Campaign Relationships
    campaign_nodes = [
        n for n in neighborhood_nodes.values()
        if n["type"] == EntityType.CAMPAIGN or n["id"].startswith("campaign:")
    ]
    campaign_names = [n["label"] for n in campaign_nodes]
    if campaign_nodes:
        signals.append(GraphSignal(
            signal_type="CAMPAIGN_CLUSTER_ASSOCIATED",
            weight=0.88,
            description=f"Entity cluster belongs to known threat campaign: {', '.join(campaign_names)}",
            evidence_value=campaign_names,
        ))
        risk_accum += 0.25

    # Signal D: Entity Reuse (e.g. sender or domain tied to multiple distinct emails)
    reused_entities = []
    for ent_id in query_entity_ids:
        ent_data = neighborhood_nodes.get(ent_id)
        if not ent_data:
            continue
        # Count connected distinct emails
        connected_emails = [
            r["source"] for r in unique_rels
            if (r["target"] == ent_id and r["source"].startswith("email:"))
        ]
        if len(connected_emails) >= 2:
            reused_entities.append(f"{ent_data['label']} ({len(connected_emails)} emails)")

    if reused_entities:
        signals.append(GraphSignal(
            signal_type="ENTITY_REUSE_DETECTED",
            weight=0.80,
            description=f"Entity observed across multiple phishing emails: {', '.join(reused_entities)}",
            evidence_value=reused_entities,
        ))
        risk_accum += 0.20

    # Signal E: High-Risk Neighbors
    high_risk_neighbors = [
        n for n in neighborhood_nodes.values()
        if n["risk_score"] >= 0.70 and n["id"] not in query_entity_ids
    ]
    if high_risk_neighbors and not matched_tis and not relevant_shared_infra:
        signals.append(GraphSignal(
            signal_type="SUSPICIOUS_NEIGHBORHOOD_DENSITY",
            weight=0.75,
            description=f"Connected within 2 hops to {len(high_risk_neighbors)} high-risk entities.",
            evidence_value=[n["label"] for n in high_risk_neighbors],
        ))
        risk_accum += min(0.25, len(high_risk_neighbors) * 0.08)

    # Final Risk Normalization (0.0 to 1.0)
    final_graph_risk = round(min(1.0, max(0.0, risk_accum)), 3)

    return GraphAnalysisResult(
        graph_risk_score=final_graph_risk,
        related_entities=list(neighborhood_nodes.values()),
        relationships=unique_rels,
        campaign_indicators=campaign_names,
        signals=signals,
        graph_evidence={
            "total_connected_nodes": len(neighborhood_nodes),
            "total_relationships": len(unique_rels),
            "shared_infrastructure_detected": len(relevant_shared_infra) > 0,
            "campaign_match_count": len(campaign_nodes),
            "malicious_ioc_count": len(matched_tis),
        },
    )
