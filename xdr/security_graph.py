"""Security knowledge graph V2 for SAFE investigations."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping

from schema.canonical_event import CanonicalEvent


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: str
    tenant_id: str
    label: str
    properties: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "tenant_id": self.tenant_id,
            "label": self.label,
            "properties": dict(self.properties),
        }


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relationship: str
    tenant_id: str
    properties: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "tenant_id": self.tenant_id,
            "properties": dict(self.properties),
        }


class SecurityKnowledgeGraph:
    """In-memory tenant-safe graph for assets, identities, detections and infra."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._tenant_index: dict[str, set[str]] = defaultdict(set)

    def ingest_event(self, event: CanonicalEvent) -> None:
        event_node = self.add_node(event.tenant_id, "event", event.event_id, event.event_type, {"category": event.category, "severity": event.severity})
        host_node = self.add_node(event.tenant_id, "asset", f"host:{event.host_id}", event.host_id, {})
        self.add_edge(event.tenant_id, host_node.node_id, event_node.node_id, "emitted")
        if event.user_id:
            user_node = self.add_node(event.tenant_id, "identity", f"user:{event.user_id}", event.user_id, {})
            self.add_edge(event.tenant_id, user_node.node_id, event_node.node_id, "performed")
        if event.process.name:
            process_node = self.add_node(
                event.tenant_id,
                "process",
                f"process:{event.host_id}:{event.process.pid or event.process.name}",
                event.process.name,
                {"pid": event.process.pid, "sha256": event.process.sha256},
            )
            self.add_edge(event.tenant_id, host_node.node_id, process_node.node_id, "ran_process")
            self.add_edge(event.tenant_id, process_node.node_id, event_node.node_id, "generated")
            if event.process.parent_name:
                parent_node = self.add_node(event.tenant_id, "process", f"process:{event.host_id}:parent:{event.process.parent_name}", event.process.parent_name, {})
                self.add_edge(event.tenant_id, parent_node.node_id, process_node.node_id, "spawned")
        if event.network.dst_ip:
            infra_node = self.add_node(event.tenant_id, "infrastructure", f"ip:{event.network.dst_ip}", event.network.dst_ip, {"port": event.network.dst_port})
            self.add_edge(event.tenant_id, event_node.node_id, infra_node.node_id, "connected_to")
        if event.network.domain:
            domain_node = self.add_node(event.tenant_id, "infrastructure", f"domain:{event.network.domain}", event.network.domain, {})
            self.add_edge(event.tenant_id, event_node.node_id, domain_node.node_id, "resolved_or_contacted")
        campaign = event.enrichment.get("campaign") if isinstance(event.enrichment, Mapping) else {}
        if isinstance(campaign, Mapping) and campaign.get("campaign_key"):
            campaign_node = self.add_node(event.tenant_id, "campaign", str(campaign["campaign_key"]), str(campaign["campaign_key"]), {})
            self.add_edge(event.tenant_id, event_node.node_id, campaign_node.node_id, "linked_to_campaign")
        mitre = event.enrichment.get("mitre") if isinstance(event.enrichment, Mapping) else {}
        if isinstance(mitre, Mapping):
            for tactic in mitre.get("tactics") or []:
                tactic_node = self.add_node(event.tenant_id, "mitre_tactic", f"mitre:{tactic}", str(tactic), {})
                self.add_edge(event.tenant_id, event_node.node_id, tactic_node.node_id, "mapped_to")

    def add_detection_relationship(self, *, tenant_id: str, event_id: str, rule_id: str, tactic: str = "") -> None:
        event_node = self.add_node(tenant_id, "event", event_id, event_id, {})
        detection_node = self.add_node(tenant_id, "detection", f"rule:{rule_id}", rule_id, {"tactic": tactic})
        self.add_edge(tenant_id, event_node.node_id, detection_node.node_id, "triggered")

    def add_node(self, tenant_id: str, node_type: str, node_id: str, label: str, properties: Mapping[str, Any]) -> GraphNode:
        tenant = str(tenant_id or "default")
        full_id = f"{tenant}:{node_id}"
        node = self.nodes.get(full_id)
        if not node:
            node = GraphNode(full_id, node_type, tenant, label, dict(properties))
            self.nodes[full_id] = node
            self._tenant_index[tenant].add(full_id)
        return node

    def add_edge(self, tenant_id: str, source: str, target: str, relationship: str, properties: Mapping[str, Any] | None = None) -> None:
        edge = GraphEdge(source, target, relationship, str(tenant_id or "default"), dict(properties or {}))
        self.edges.append(edge)

    def tenant_view(self, tenant_id: str) -> dict[str, Any]:
        tenant = str(tenant_id or "default")
        node_ids = self._tenant_index.get(tenant, set())
        edges = [edge for edge in self.edges if edge.tenant_id == tenant and edge.source in node_ids and edge.target in node_ids]
        return {
            "tenant_id": tenant,
            "nodes": [self.nodes[node_id].to_dict() for node_id in sorted(node_ids)],
            "edges": [edge.to_dict() for edge in edges],
            "node_count": len(node_ids),
            "edge_count": len(edges),
        }

    def pivots_for(self, *, tenant_id: str, node_id_fragment: str) -> dict[str, Any]:
        view = self.tenant_view(tenant_id)
        fragment = str(node_id_fragment or "").lower()
        matching = [node for node in view["nodes"] if fragment in node["node_id"].lower() or fragment in node["label"].lower()]
        matching_ids = {node["node_id"] for node in matching}
        edges = [edge for edge in view["edges"] if edge["source"] in matching_ids or edge["target"] in matching_ids]
        return {"tenant_id": tenant_id, "matches": matching, "edges": edges}
