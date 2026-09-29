"""
TRINETRA — Graph Intelligence Engine Tests (Phase 10)

Tests:
- Entity and relationship creations in NetworkX store
- Dynamic Shared Infrastructure correlation (Domain A, B, C -> IP X)
- Subgraph extraction (k-hop neighborhood)
- Multi-signal graph risk scoring:
    * Known malicious indicator connection
    * Shared infrastructure detection
    * Campaign clustering
    * Entity reuse
    * Safe/legitimate baseline
- API endpoints for overview, email ego-subgraph, entity details, campaigns,
  threat indicators, shared infrastructure, and ingestion.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.graph_engine import (
    EntityType,
    NetworkXGraphStore,
    RelationType,
    calculate_graph_risk,
    graph_store,
)

client = TestClient(app)


# ---------------------------------------------------------------------------
# Unit Tests: NetworkX Graph Store
# ---------------------------------------------------------------------------

class TestNetworkXGraphStore:

    def test_store_initialization_seeds(self):
        """Verify the graph store initializes with real-world correlation clusters."""
        assert graph_store.graph.number_of_nodes() > 10
        assert graph_store.graph.number_of_edges() > 10

    def test_add_node_and_get(self):
        store = NetworkXGraphStore()
        store.add_node("domain:test-phish.com", EntityType.DOMAIN, "test-phish.com", risk_score=0.85)
        node = store.get_node("domain:test-phish.com")
        assert node is not None
        assert node["id"] == "domain:test-phish.com"
        assert node["entity_type"] == EntityType.DOMAIN
        assert node["risk_score"] == 0.85

    def test_add_edge_and_neighbors(self):
        store = NetworkXGraphStore()
        store.add_node("email:msg-1", EntityType.EMAIL, "Phish 1")
        store.add_node("sender:bad@actor.com", EntityType.SENDER, "bad@actor.com")
        store.add_edge("email:msg-1", "sender:bad@actor.com", RelationType.SENT_BY)

        out_nbrs = store.get_neighbors("email:msg-1", direction="out")
        assert len(out_nbrs) == 1
        assert out_nbrs[0]["id"] == "sender:bad@actor.com"

        in_nbrs = store.get_neighbors("sender:bad@actor.com", direction="in")
        assert len(in_nbrs) == 1
        assert in_nbrs[0]["id"] == "email:msg-1"

    def test_shared_infrastructure_correlation(self):
        """
        Test the core Phase 10 requirement:
        Email A -> Domain A -> IP X
        Email B -> Domain B -> IP X
        TRINETRA must identify shared infrastructure.
        """
        store = NetworkXGraphStore()
        # Create unique test IP
        test_ip = "198.51.100.99"
        ip_id = f"ip:{test_ip}"
        store.add_node(ip_id, EntityType.IP, test_ip, risk_score=0.90, asn="AS12345", country="RO")

        # Domain A
        dom_a = "domain:phish-alpha.net"
        store.add_node(dom_a, EntityType.DOMAIN, "phish-alpha.net", risk_score=0.85)
        store.add_edge(dom_a, ip_id, RelationType.RESOLVES_TO)

        # Domain B
        dom_b = "domain:phish-beta.net"
        store.add_node(dom_b, EntityType.DOMAIN, "phish-beta.net", risk_score=0.88)
        store.add_edge(dom_b, ip_id, RelationType.RESOLVES_TO)

        findings = store.find_shared_infrastructure()
        matched = [f for f in findings if f.ip_address == test_ip]
        assert len(matched) == 1
        f = matched[0]
        assert "phish-alpha.net" in f.connected_domains
        assert "phish-beta.net" in f.connected_domains
        assert f.is_malicious is True

        # Verify dynamic SHARES_INFRASTRUCTURE edge was created between domains
        assert store.graph.has_edge(dom_a, dom_b)

    def test_subgraph_extraction(self):
        store = NetworkXGraphStore()
        nodes, edges = store.get_subgraph("email:msg-fin7-001", max_hops=2)
        assert len(nodes) >= 3
        node_ids = {n.id for n in nodes}
        assert "email:msg-fin7-001" in node_ids
        assert "sender:security-update@micros0ft-support.com" in node_ids

    def test_to_react_flow_format(self):
        store = NetworkXGraphStore()
        rf = store.to_react_flow()
        assert len(rf.nodes) > 0
        assert len(rf.edges) > 0
        assert "stats" in rf.model_dump()
        first_node = rf.nodes[0]
        assert "position" in first_node.model_dump()
        assert "data" in first_node.model_dump()
        assert first_node.type == "custom"


# ---------------------------------------------------------------------------
# Unit Tests: Multi-Signal Graph Risk Scoring
# ---------------------------------------------------------------------------

class TestGraphRiskScoring:

    def test_fin7_email_high_graph_risk(self):
        """
        Email A from FIN7 campaign should produce high graph risk due to:
        - Malicious indicator (CIAD-2023-0198)
        - Shared infrastructure (185.220.101.5)
        - Campaign association (CAMPAIGN-FIN7-M365)
        """
        res = calculate_graph_risk(
            email_id="msg-fin7-001",
            sender_email="security-update@micros0ft-support.com",
            sender_domain="micros0ft-support.com",
            urls=["https://secure-banking-update.xyz/verify-account"],
        )
        assert res.graph_risk_score >= 0.75
        signal_types = {s.signal_type for s in res.signals}
        assert "KNOWN_MALICIOUS_INDICATOR_CONNECTED" in signal_types
        assert "SHARED_INFRASTRUCTURE_DETECTED" in signal_types
        assert "CAMPAIGN_CLUSTER_ASSOCIATED" in signal_types
        assert len(res.campaign_indicators) > 0

    def test_legitimate_email_low_graph_risk(self):
        """
        Legitimate enterprise email should produce near-zero graph risk.
        """
        res = calculate_graph_risk(
            email_id="msg-legit-006",
            sender_email="ciso@enterprise-corp.com",
            sender_domain="enterprise-corp.com",
            urls=["https://intranet.enterprise-corp.com/reports/q3"],
        )
        assert res.graph_risk_score <= 0.15
        assert len(res.signals) == 0

    def test_ingest_flag_adds_new_email(self):
        new_id = "test-new-email-123"
        res = calculate_graph_risk(
            email_id=new_id,
            sender_email="hacker@bad-domain-xyz.com",
            sender_domain="bad-domain-xyz.com",
            urls=["http://bad-domain-xyz.com/steal"],
            ingest=True,
            subject="Urgent Security Action",
        )
        assert graph_store.graph.has_node(f"email:{new_id}")
        assert graph_store.graph.has_node("sender:hacker@bad-domain-xyz.com")
        assert graph_store.graph.has_node("domain:bad-domain-xyz.com")


# ---------------------------------------------------------------------------
# Integration Tests: Graph Intelligence API Endpoints
# ---------------------------------------------------------------------------

class TestGraphEndpoints:

    def test_get_graph_overview(self):
        resp = client.get("/api/v1/graph/overview")
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data
        assert "stats" in data
        assert len(data["nodes"]) > 5

    def test_get_graph_overview_filtered(self):
        resp = client.get("/api/v1/graph/overview?entity_filter=Domain,IP")
        assert resp.status_code == 200
        data = resp.json()
        for node in data["nodes"]:
            assert node["data"]["type"] in ("Domain", "IP")

    def test_get_email_subgraph(self):
        resp = client.get("/api/v1/graph/email/msg-fin7-001")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["nodes"]) >= 3

    def test_get_email_subgraph_not_found(self):
        resp = client.get("/api/v1/graph/email/nonexistent-msg-id-xyz")
        assert resp.status_code == 404

    def test_get_entity_details(self):
        resp = client.get("/api/v1/graph/entity?node_id=ip:185.220.101.5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["entity"]["id"] == "ip:185.220.101.5"
        assert data["total_neighbors"] >= 3

    def test_get_campaigns(self):
        resp = client.get("/api/v1/graph/campaigns")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 2
        names = [c["name"] for c in data]
        assert "CAMPAIGN-FIN7-M365" in names

    def test_get_indicators(self):
        resp = client.get("/api/v1/graph/indicators")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        labels = [i["label"] for i in data]
        assert "CIAD-2023-0198" in labels

    def test_get_shared_infrastructure(self):
        resp = client.get("/api/v1/graph/infrastructure")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        ips = [item["ip_address"] for item in data]
        assert "185.220.101.5" in ips

    def test_post_analyze(self):
        payload = {
            "email_id": "msg-fin7-001",
            "sender_email": "security-update@micros0ft-support.com",
            "sender_domain": "micros0ft-support.com",
            "urls": ["https://secure-banking-update.xyz/verify-account"],
        }
        resp = client.post("/api/v1/graph/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "graph_risk_score" in data
        assert data["graph_risk_score"] > 0.7

    def test_post_ingest(self):
        payload = {
            "email_id": "api-ingested-email-999",
            "subject": "Wire Transfer Urgent Verification",
            "sender_email": "attacker@fake-bank.xyz",
            "sender_domain": "fake-bank.xyz",
            "urls": ["https://fake-bank.xyz/portal"],
            "ips": ["198.51.100.50"],
            "brand_impersonated": "chase",
            "campaign_id": "CAMPAIGN-FIN-WIRE",
            "threat_indicators": ["CIAD-2024-9999"],
            "risk_score": 0.95,
            "decision": "QUARANTINE",
        }
        resp = client.post("/api/v1/graph/ingest", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert graph_store.graph.has_node("email:api-ingested-email-999")
