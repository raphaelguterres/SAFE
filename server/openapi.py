"""OpenAPI helpers for SAFE."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_PATH = ROOT / "openapi" / "safe-api.yaml"


def load_openapi_yaml(path: str | Path = OPENAPI_PATH) -> str:
    return Path(path).read_text(encoding="utf-8")


def load_openapi_spec(path: str | Path = OPENAPI_PATH) -> dict[str, Any]:
    return yaml.safe_load(load_openapi_yaml(path))


def openapi_json_response(jsonify_fn):
    return jsonify_fn(load_openapi_spec())


def openapi_yaml_response(response_cls):
    return response_cls(load_openapi_yaml(), mimetype="application/yaml")
