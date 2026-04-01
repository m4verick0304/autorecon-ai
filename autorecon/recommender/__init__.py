"""Recommendation engine for exploit and vulnerability suggestions."""

from autorecon.recommender.exploit_mapper import ExploitMapper, ExploitMatch
from autorecon.recommender.vulnerability_db import VulnerabilityDB

__all__ = ["ExploitMapper", "ExploitMatch", "VulnerabilityDB"]
