# Made by Sn0w8ird

"""Pluggable operator payloads: load from ``CPOINTED_PAYLOAD_DIR`` or target metadata."""

from cpointed.payloads.bundle import OperatorBundle, operator_bundle_for_target

__all__ = ["OperatorBundle", "operator_bundle_for_target"]
