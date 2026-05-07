"""Compatibility wrapper for the modular SAFE agent package."""

from netguard_agent import NetGuardAgent, main

__all__ = ["NetGuardAgent", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
