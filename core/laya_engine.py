"""Decision Engine Adapter (Backward Compatible with LayaEngine).

Defaults to TypeSafe JEV as the primary System 1 decision model,
with the ability to switch dynamically to Local Laya INT8 ONNX or Custom endpoints.
"""

from typing import Dict, Any, Optional
from core.decision_engine import decision_engine_singleton, DecisionEngine


class LayaEngine:
    """Wrapper delegating to the master pluggable DecisionEngine."""

    def __init__(self, onnx_path: Optional[str] = None):
        self.engine = decision_engine_singleton
        if onnx_path:
            self.engine.set_provider("local_laya", onnx_path=onnx_path)

    def set_provider(self, provider_key: str, **kwargs):
        """Switch active provider: 'typesafe_jev', 'local_laya', or 'custom'."""
        self.engine.set_provider(provider_key, **kwargs)

    def get_active_provider_name(self) -> str:
        return self.engine.get_active_provider_name()

    def evaluate(self, state: str, questions: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate using the active decision model."""
        return self.engine.evaluate(state, questions)


# Global singleton adapter
laya_singleton = LayaEngine()
