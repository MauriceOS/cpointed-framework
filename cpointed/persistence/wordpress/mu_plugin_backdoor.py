# Made by Sn0w8ird

"""Compatibility name — delegates to the lab mu-plugin probe (non-executable payload)."""

from cpointed.persistence.wordpress.mu_plugin import MuPluginPersistence

MuPluginBackdoor = MuPluginPersistence

__all__ = ["MuPluginBackdoor", "MuPluginPersistence"]
