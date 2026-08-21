from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AssetBase(BaseModel):
    asset_id: str = Field(min_length=1, max_length=256)
    asset_type: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    service_id: str | None = Field(default=None, max_length=256)
    environment: str | None = Field(default=None, max_length=128)
    criticality: float = Field(default=0.5, ge=0.0, le=1.0)
    owner_team: str | None = Field(default=None, max_length=128)
    ip_address: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(default=None, max_length=10_000)
    network_zone: str | None = Field(default=None, max_length=128)
    expected_peers: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    active: bool = True


class AssetCreate(AssetBase):
    pass


class AssetUpsert(BaseModel):
    """Body for `PUT /assets/{asset_id}` — `asset_id` comes from the path.

    Used by self-enrolling collectors, which re-run enrollment on every boot and
    must not fail once the asset already exists (`POST` deliberately still 409s).
    """

    asset_type: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    service_id: str | None = Field(default=None, max_length=256)
    environment: str | None = Field(default=None, max_length=128)
    criticality: float = Field(default=0.5, ge=0.0, le=1.0)
    owner_team: str | None = Field(default=None, max_length=128)
    ip_address: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(default=None, max_length=10_000)
    network_zone: str | None = Field(default=None, max_length=128)
    expected_peers: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    active: bool = True


class AssetUpdate(BaseModel):
    asset_type: str | None = Field(default=None, max_length=128)
    name: str | None = Field(default=None, max_length=256)
    service_id: str | None = Field(default=None, max_length=256)
    environment: str | None = Field(default=None, max_length=128)
    criticality: float | None = Field(default=None, ge=0.0, le=1.0)
    owner_team: str | None = Field(default=None, max_length=128)
    ip_address: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(default=None, max_length=10_000)
    network_zone: str | None = Field(default=None, max_length=128)
    expected_peers: list[str] | None = None
    tags: dict[str, str] | None = None
    active: bool | None = None


class AssetRead(AssetBase):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    created_at: datetime
    updated_at: datetime


class TopologyNode(BaseModel):
    id: str
    kind: str
    label: str | None = None


class TopologyEdge(BaseModel):
    source: str
    target: str
    relation: str = "expected_peer"


class TopologyResponse(BaseModel):
    asset_id: str
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


class BaselineStats(BaseModel):
    sample_count: int = 0
    mean_score: float | None = None
    p95_score: float | None = None
    status: str = "ready"
    capability: str = "asset_baseline"
    reason: str | None = None
    retry_after_seconds: int | None = None


class BaselineResponse(BaseModel):
    asset_id: str
    window_days: int = 7
    stats: BaselineStats
