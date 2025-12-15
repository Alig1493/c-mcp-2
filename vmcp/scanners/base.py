"""Base scanner interface and common functionality."""
from abc import ABC, abstractmethod
from typing import Any

from vmcp.models import VulnerabilityModel


class BaseScanner(ABC):
    """Base class for all vulnerability scanners."""

    def __init__(self, repo_path: str, org_name: str, repo_name: str):
        self.repo_path = repo_path
        self.org_name = org_name
        self.repo_name = repo_name

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner name."""
        pass

    @abstractmethod
    async def scan(self) -> list[VulnerabilityModel]:
        """Execute the scan and return vulnerabilities."""
        pass

    def is_applicable(self) -> bool:
        """Check if scanner is applicable for this repository."""
        return True
