"""Validation of complete Enterprise record arrays; no file or replay exporter."""
import json
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parent


def records_from_bytes(raw):
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("Expected an API record array or gh --slurp array of pages")
    records = []
    for item in data:
        records.extend(item if isinstance(item, list) else [item])
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Each usage record must be an object")
        if record.get("type") not in ("request", "response"):
            raise ValueError("Unknown usage record type")
        stamp = record.get("@timestamp")
        if type(stamp) is not int or stamp <= 0 or stamp > int(time.time() * 1000) + 300000:
            raise ValueError("Expected a valid millisecond @timestamp")
        if type(record.get("user_id")) is not int or record["user_id"] <= 0:
            raise ValueError("Expected a positive numeric user_id")
        if not isinstance(record.get("body"), str):
            raise ValueError("Expected a JSON-encoded body string")
        if not isinstance(record.get("github_request_id"), str) or not record["github_request_id"]:
            raise ValueError("Missing github_request_id for request/response correlation")
    return records
