from datetime import datetime
from enum import StrEnum
from typing import Literal, Optional, Sequence

from pydantic import BaseModel, Field


type VulnerabilitySeverity = Literal[
    "UNKNOWN",
    "NONE",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    "WARNING",
]
type VulnerabilitySource = Literal["osv", "trivy", "yara"]


class ScmProvider(StrEnum):
    """Types of scm providers."""

    AWS_CODE_COMMIT = "aws_code_commit"
    AZURE_DEVOPS = "azure_devops"
    BITBUCKET = "bitbucket"
    GITEA = "gitea"
    GITHUB = "github"
    GITLAB = "gitlab"


class VulnerabilityScoreModel(BaseModel):
    """Vulnerability score model for storage."""

    type: str
    value: float
    version: Optional[str] = None


class VulnerabilityReferenceModel(BaseModel):
    """Vulnerability reference model for storage."""

    type: str
    url: str


class VulnerabilityModel(BaseModel):
    """Vulnerability model for storage."""

    id: str
    identifier_type: str
    affected_range: str
    aliases: Sequence[str] = Field(default_factory=list)
    details: str
    fixed_version: Optional[str] = None
    published: datetime | None = None
    references: Sequence[VulnerabilityReferenceModel] = Field(default_factory=list)
    scores: Sequence[VulnerabilityScoreModel] = Field(default_factory=list)
    severity: VulnerabilitySeverity
    source: VulnerabilitySource | None = None
    summary: str
    # SAST-specific fields
    rule_name: Optional[str] = None
    rule_id: Optional[str] = None
    confidence: Optional[str] = None
    file_location: Optional[str] = None
    line_range: Optional[str] = None
    categories: Sequence[str] = Field(default_factory=list)

