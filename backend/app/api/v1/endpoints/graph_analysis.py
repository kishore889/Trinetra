"""
TRINETRA — Graph Intelligence API Endpoints (Phase 10)

GET  /api/v1/graph/overview          → Full or filtered React Flow graph with stats
GET  /api/v1/graph/email/{email_id}  → Ego-subgraph around specific email for investigation
GET  /api/v1/graph/entity            → Inspect neighbors and relationships of a specific node
GET  /api/v1/graph/campaigns         → List identified campaigns and their entity networks
GET  /api/v1/graph/indicators        → List threat indicators connected in the graph
GET  /api/v1/graph/infrastructure    → Correlated shared infrastructure (IPs co-hosting domains)
POST /api/v1/graph/analyze           → Multi-signal graph risk scoring for email entities
POST /api/v1/graph/ingest            → Add analyzed email and associated entities to graph
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.services.graph_engine import (
    ALL_ENTITY_TYPES,
    ALL_RELATION_TYPES,
    EntityType,
    GraphAnalysisResult,
    ReactFlowGraph,
    RelationType,
    SharedInfrastructureFinding,
    calculate_graph_risk,
    graph_store,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class GraphAnalyzeRequest(BaseModel):
    email_id: str = Field(..., description="Unique email message ID")
    sender_email: Optional[str] = None
    sender_domain: Optional[str] = None
    subject: Optional[str] = None
    urls: List[str] = []
    ips: List[str] = []
    threat_indicators: List[str] = []
    ingest: bool = False


class IngestEmailEntitiesRequest(BaseModel):
    email_id: str
    subject: str
    sender_email: Optional[str] = None
    sender_domain: Optional[str] = None
    urls: List[str] = []
    ips: List[str] = []
    brand_impersonated: Optional[str] = None
    campaign_id: Optional[str] = None
    threat_indicators: List[str] = []
    risk_score: float = 0.5
    decision: str = "WARN"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview", response_model=ReactFlowGraph)
async def get_graph_overview(
    entity_filter: Optional[str] = Query(None, description="Comma-separated entity types to include"),
    max_hops: int = Query(3, ge=1, le=5),
):
    """
    Returns the SOC threat intelligence graph formatted directly for React Flow.
    Supports filtering by entity type (e.g. Email, Domain, URL, IP, Campaign, ThreatIndicator).
    """
    rf_graph = graph_store.to_react_flow(center_node_id=None, max_hops=max_hops)

    if entity_filter:
        allowed = {et.strip() for et in entity_filter.split(",") if et.strip()}
        filtered_nodes = [n for n in rf_graph.nodes if n.data.get("type") in allowed]
        node_ids = {n.id for n in filtered_nodes}
        filtered_edges = [
            e for e in rf_graph.edges
            if e.source in node_ids and e.target in node_ids
        ]
        rf_graph.nodes = filtered_nodes
        rf_graph.edges = filtered_edges
        rf_graph.stats["total_nodes"] = len(filtered_nodes)
        rf_graph.stats["total_edges"] = len(filtered_edges)

    return rf_graph


@router.get("/email/{email_id}", response_model=ReactFlowGraph)
async def get_email_subgraph(
    email_id: str,
    max_hops: int = Query(2, ge=1, le=4),
):
    """
    Returns the ego-subgraph centered around a specific email for investigation.
    """
    node_id = f"email:{email_id.strip()}" if not email_id.startswith("email:") else email_id.strip()
    if not graph_store.graph.has_node(node_id):
        # Check if node exists by raw id
        if graph_store.graph.has_node(email_id.strip()):
            node_id = email_id.strip()
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Email node '{email_id}' not found in graph.",
            )

    return graph_store.to_react_flow(center_node_id=node_id, max_hops=max_hops)


@router.get("/entity")
async def get_entity_details(
    node_id: str = Query(..., description="Full node ID, e.g., 'domain:micros0ft-support.com' or 'ip:185.220.101.5'"),
    direction: str = Query("both", pattern="^(in|out|both)$"),
):
    """
    Returns node attributes and all direct neighbors with their relation types.
    """
    node = graph_store.get_node(node_id)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entity '{node_id}' not found in threat graph.",
        )

    neighbors = graph_store.get_neighbors(node_id, direction=direction)
    return {
        "entity": node,
        "total_neighbors": len(neighbors),
        "neighbors": neighbors,
    }


@router.get("/campaigns")
async def list_campaigns():
    """
    Returns all detected threat campaigns and their associated entity networks.
    """
    campaigns = []
    for node_id, data in graph_store.graph.nodes(data=True):
        if data.get("entity_type") == EntityType.CAMPAIGN:
            neighbors = graph_store.get_neighbors(node_id, direction="both")
            campaigns.append({
                "id": node_id,
                "name": data.get("label", node_id),
                "risk_score": data.get("risk_score", 0.0),
                "properties": {k: v for k, v in data.items() if k not in ("entity_type", "label", "risk_score")},
                "associated_entities_count": len(neighbors),
                "associated_entities": [
                    {"id": nbr["id"], "type": nbr.get("entity_type"), "label": nbr.get("label")}
                    for nbr in neighbors
                ],
            })
    return campaigns


@router.get("/indicators")
async def list_graph_indicators():
    """
    Returns all ThreatIndicator nodes and their connections in the graph.
    """
    indicators = []
    for node_id, data in graph_store.graph.nodes(data=True):
        if data.get("entity_type") == EntityType.THREAT_INDICATOR:
            neighbors = graph_store.get_neighbors(node_id, direction="both")
            indicators.append({
                "id": node_id,
                "label": data.get("label", node_id),
                "risk_score": data.get("risk_score", 0.0),
                "properties": {k: v for k, v in data.items() if k not in ("entity_type", "label", "risk_score")},
                "matched_entities": [
                    {"id": nbr["id"], "type": nbr.get("entity_type"), "label": nbr.get("label")}
                    for nbr in neighbors
                ],
            })
    return indicators


@router.get("/infrastructure", response_model=List[SharedInfrastructureFinding])
async def get_shared_infrastructure():
    """
    Correlates and returns shared infrastructure findings:
    IP addresses hosting multiple distinct domains or phishing URLs.
    """
    return graph_store.find_shared_infrastructure()


@router.post("/analyze", response_model=GraphAnalysisResult)
async def analyze_email_graph(req: GraphAnalyzeRequest):
    """
    Calculates multi-signal graph risk score and neighborhood evidence for an email.
    """
    return calculate_graph_risk(
        email_id=req.email_id,
        sender_email=req.sender_email,
        sender_domain=req.sender_domain,
        urls=req.urls,
        ips=req.ips,
        threat_indicators=req.threat_indicators,
        ingest=req.ingest,
        subject=req.subject,
    )


@router.post("/ingest")
async def ingest_email(req: IngestEmailEntitiesRequest):
    """
    Ingests an analyzed email and its entities into the persistent graph store.
    """
    email_node_id = f"email:{req.email_id.strip()}"
    graph_store.add_node(
        email_node_id,
        EntityType.EMAIL,
        label=req.subject or req.email_id,
        risk_score=req.risk_score,
        subject=req.subject,
        decision=req.decision,
    )

    if req.sender_email:
        s_id = f"sender:{req.sender_email.lower().strip()}"
        graph_store.add_node(s_id, EntityType.SENDER, label=req.sender_email, risk_score=req.risk_score)
        graph_store.add_edge(email_node_id, s_id, RelationType.SENT_BY)

        if req.sender_domain:
            d_id = f"domain:{req.sender_domain.lower().strip()}"
            graph_store.add_node(d_id, EntityType.DOMAIN, label=req.sender_domain, risk_score=req.risk_score)
            graph_store.add_edge(s_id, d_id, RelationType.HOSTED_ON)

            if req.brand_impersonated:
                b_id = f"brand:{req.brand_impersonated.lower().strip()}"
                graph_store.add_node(b_id, EntityType.BRAND, label=req.brand_impersonated, risk_score=0.1)
                graph_store.add_edge(d_id, b_id, RelationType.IMPERSONATES)

    for u in req.urls:
        u_id = f"url:{u.strip()}"
        graph_store.add_node(u_id, EntityType.URL, label=u, risk_score=req.risk_score)
        graph_store.add_edge(email_node_id, u_id, RelationType.CONTAINS)

    for ip in req.ips:
        ip_id = f"ip:{ip.strip()}"
        graph_store.add_node(ip_id, EntityType.IP, label=ip, risk_score=req.risk_score)
        if req.sender_domain:
            d_id = f"domain:{req.sender_domain.lower().strip()}"
            graph_store.add_edge(d_id, ip_id, RelationType.RESOLVES_TO)

    if req.campaign_id:
        c_id = f"campaign:{req.campaign_id.strip()}"
        graph_store.add_node(c_id, EntityType.CAMPAIGN, label=req.campaign_id, risk_score=0.90)
        graph_store.add_edge(c_id, email_node_id, RelationType.ASSOCIATED_WITH)

    for ti in req.threat_indicators:
        ti_id = f"ti:{ti.strip()}"
        graph_store.add_node(ti_id, EntityType.THREAT_INDICATOR, label=ti, risk_score=0.95)
        graph_store.add_edge(email_node_id, ti_id, RelationType.MATCHES)

    return {
        "status": "success",
        "message": f"Email '{req.email_id}' and associated entities ingested into graph.",
        "node_id": email_node_id,
        "graph_stats": {
            "total_nodes": graph_store.graph.number_of_nodes(),
            "total_edges": graph_store.graph.number_of_edges(),
        },
    }
