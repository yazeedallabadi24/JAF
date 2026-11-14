"""JAF Core: multi-hop firewall engine (rules + TypeSafe Jev via OpenRouter)."""

from .config import Settings
from .orchestrator import Blocked, Firewall
from .verdict import Action, Category, Hop, Verdict

__all__ = ["Action", "Blocked", "Category", "Firewall", "Hop", "Settings", "Verdict"]
