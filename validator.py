#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path


def is_hex(value, expected_length=None):
    if not isinstance(value, str):
        return False
    if len(value) % 2 != 0:
        return False
    if expected_length is not None and len(value) != expected_length:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def parse_utc_timestamp(value):
    if not isinstance(value, str):
        return False
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return dt.tzinfo is None and dt.isoformat() + "Z" == value
    except ValueError:
        return False


def canonicalize_hmac_payload(payload):
    frm = payload["from"]
    to = payload["to"]
    user_id = payload["userId"]
    payload_type = payload["type"]
    timestamp = payload["timestamp"]
    origin_code = payload["originCode"]
    from_lat = format(float(frm["lat"]), ".6f")
    from_lon = format(float(frm["lon"]), ".6f")
    to_lat = format(float(to["lat"]), ".6f")
    to_lon = format(float(to["lon"]), ".6f")
    return f"{user_id}|{payload_type}|{timestamp}|{from_lat}:{from_lon}|{to_lat}:{to_lon}|{origin_code}"


def validate_hmac_payload(payload):
    errors = []
    required = ["userId", "type", "from", "to", "timestamp", "originCode", "signature"]
    for key in required:
        if key not in payload:
            errors.append(f"missing required field: {key}")

    if errors:
        return {"valid": False, "errors": errors, "mode": "hmac"}

    try:
        frm = payload["from"]
        to = payload["to"]
        lat1 = float(frm["lat"])
        lon1 = float(frm["lon"])
        lat2 = float(to["lat"])
        lon2 = float(to["lon"])
    except (TypeError, ValueError, KeyError):
        errors.append("from/to coordinates must be numeric latitude/longitude pairs")
        lat1 = lon1 = lat2 = lon2 = None

    if lat1 is not None:
        if not (-90.0 <= lat1 <= 90.0):
            errors.append("from.lat is out of range [-90, 90]")
        if not (-180.0 <= lon1 <= 180.0):
            errors.append("from.lon is out of range [-180, 180]")
        if not (-90.0 <= lat2 <= 90.0):
            errors.append("to.lat is out of range [-90, 90]")
        if not (-180.0 <= lon2 <= 180.0):
            errors.append("to.lon is out of range [-180, 180]")

    if not parse_utc_timestamp(payload["timestamp"]):
        errors.append("timestamp must be ISO-8601 UTC in the form YYYY-MM-DDTHH:MM:SSZ")

    expected_origin = f"GUN-{payload['userId']}-ORIGIN-{format(float(payload['to']['lat']), '.6f')}:{format(float(payload['to']['lon']), '.6f')}"
    if payload.get("originCode") != expected_origin:
        errors.append(f"originCode mismatch: expected {expected_origin}")

    canonical = canonicalize_hmac_payload(payload)
    if not payload.get("signature"):
        errors.append("missing signature")
    elif not is_hex(payload["signature"], 64):
        errors.append("signature must be a 64-character hex string")

    return {
        "valid": not errors,
        "mode": "hmac",
        "canonical_string": canonical,
        "errors": errors,
    }


def validate_ownership_payload(payload):
    errors = []
    required_top = ["payload_hash", "leaf_hash", "origin_merkle_root", "ownership_claim", "signature_bundle", "bitcoin_anchor"]
    for key in required_top:
        if key not in payload:
            errors.append(f"missing required field: {key}")

    if errors:
        return {"valid": False, "errors": errors, "mode": "ownership"}

    if not is_hex(payload["payload_hash"], 64):
        errors.append("payload_hash must be a 64-character hex SHA-256 digest")
    if not is_hex(payload["leaf_hash"], 64):
        errors.append("leaf_hash must be a 64-character hex SHA-256 digest")
    if not is_hex(payload["origin_merkle_root"], 64):
        errors.append("origin_merkle_root must be a 64-character hex digest")

    claim = payload["ownership_claim"]
    required_claim = ["claim_type", "claimant", "asset_id", "merkle_root", "timestamp"]
    for key in required_claim:
        if key not in claim:
            errors.append(f"missing ownership_claim field: {key}")

    if isinstance(claim, dict):
        if claim.get("claim_type") != "OWNERSHIP_ASSERTION":
            errors.append("ownership_claim.claim_type must be OWNERSHIP_ASSERTION")
        if not claim.get("claimant"):
            errors.append("ownership_claim.claimant is required")
        if not claim.get("asset_id"):
            errors.append("ownership_claim.asset_id is required")
        if claim.get("merkle_root") != payload.get("origin_merkle_root"):
            errors.append("ownership_claim.merkle_root must equal origin_merkle_root")
        if not parse_utc_timestamp(claim.get("timestamp")):
            errors.append("ownership_claim.timestamp must be ISO-8601 UTC in the form YYYY-MM-DDTHH:MM:SSZ")

    bundle = payload["signature_bundle"]
    required_bundle = ["prefix", "signature_algorithm", "public_key", "signature"]
    for key in required_bundle:
        if key not in bundle:
            errors.append(f"missing signature_bundle field: {key}")
    if isinstance(bundle, dict):
        if bundle.get("prefix") != "00":
            errors.append("signature_bundle.prefix must be '00'")
        if bundle.get("signature_algorithm") != "secp256k1":
            errors.append("signature_bundle.signature_algorithm must be secp256k1")
        if not isinstance(bundle.get("public_key"), str):
            errors.append("signature_bundle.public_key must be a string")
        else:
            pub = bundle["public_key"]
            if not is_hex(pub, 66):
                errors.append("signature_bundle.public_key must be a 66-character hex compressed secp256k1 public key")
            elif not pub.startswith(("02", "03")):
                errors.append("signature_bundle.public_key must use a compressed secp256k1 format starting with 02 or 03")
        if not isinstance(bundle.get("signature"), str):
            errors.append("signature_bundle.signature must be a string")
        else:
            sig = bundle["signature"]
            if len(sig) % 2 != 0 or len(sig) < 128 or len(sig) > 200:
                errors.append("signature_bundle.signature length is outside expected DER-size range")
            if not is_hex(sig):
                errors.append("signature_bundle.signature must be hex-encoded")

    bitcoin = payload["bitcoin_anchor"]
    required_anchor = ["chain", "block_height", "block_hash"]
    for key in required_anchor:
        if key not in bitcoin:
            errors.append(f"missing bitcoin_anchor field: {key}")
    if isinstance(bitcoin, dict):
        if bitcoin.get("chain") != "bitcoin-regtest":
            errors.append("bitcoin_anchor.chain must be bitcoin-regtest")
        if not isinstance(bitcoin.get("block_height"), int) or bitcoin["block_height"] <= 0:
            errors.append("bitcoin_anchor.block_height must be a positive integer")
        if not is_hex(bitcoin.get("block_hash"), 64):
            errors.append("bitcoin_anchor.block_hash must be a 64-character hex block hash")

    hash_input = {k: v for k, v in payload.items() if k != "payload_hash"}
    canonical = json.dumps(hash_input, separators=(",", ":"), sort_keys=True)
    actual_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if payload["payload_hash"] != actual_hash:
        errors.append("payload_hash does not match the canonical JSON payload")

    return {
        "valid": not errors,
        "mode": "ownership",
        "canonical_json_hash": actual_hash,
        "errors": errors,
    }


def detect_mode(payload):
    if isinstance(payload, dict) and "ownership_claim" in payload and "signature_bundle" in payload:
        return "ownership"
    return "hmac"


def main():
    parser = argparse.ArgumentParser(description="Validate Genesis ownership or HMAC payloads.")
    parser.add_argument("--payload", required=True, help="Path to a JSON payload file.")
    parser.add_argument("--secret", help="Optional secret for HMAC validation only.")
    args = parser.parse_args()

    try:
        with open(args.payload, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as exc:
        print(json.dumps({"valid": False, "errors": [f"unable to read payload: {exc}"], "mode": "unknown"}, indent=2))
        return 1

    mode = detect_mode(payload)
    if mode == "ownership":
        result = validate_ownership_payload(payload)
    else:
        if args.secret is None:
            print(json.dumps({"valid": False, "errors": ["--secret is required for HMAC payload validation"], "mode": "hmac"}, indent=2))
            return 1
        result = validate_hmac_payload(payload)

    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
