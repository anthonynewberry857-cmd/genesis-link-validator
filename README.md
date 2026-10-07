# genesis-link-validator

Automatic validator for cryptographically signed `GENESIS_LINK` payloads with HMAC-SHA256 verification.

## Purpose

This project validates a signed `GENESIS_LINK` payload using a deterministic canonicalization rule and HMAC-SHA256.

It enforces the following rules:

- The payload must be valid JSON.
- Required fields must be present.
- `from` and `to` coordinates must be valid latitude/longitude values.
- `timestamp` must be ISO-8601 UTC in the form `YYYY-MM-DDTHH:MM:SSZ`.
- `originCode` must match the expected rule based on `userId` and the destination coordinate.
- A canonical payload string is generated in a strict order.
- HMAC-SHA256 is computed over that canonical string using a secret key.
- The computed digest must equal the supplied hex signature.

## Canonical string

The canonical payload string format is:

```text
{userId}|{type}|{timestamp}|{from_lat}:{from_lon}|{to_lat}:{to_lon}|{originCode}
```

with coordinates formatted to exactly 6 decimal places.

Example for the payload in `sample_payload.json`:

```text
557574855|GENESIS_LINK|2026-03-04T10:15:30Z|38.969600:-122.652600|38.969551:-122.652608|GUN-557574855-ORIGIN-38.969551:-122.652608
```

## Expected origin code rule

```text
GUN-{userId}-ORIGIN-{to_lat}:{to_lon}
```

with the destination (`to`) coordinates formatted to 6 decimal places.

## How to run

From the repository root:

```bash
python validator.py --payload sample_payload.json --secret <hex_secret>
```

The script prints JSON output containing:

- `valid`: true or false
- `canonical_string`
- `computed_hmac_sha256`
- `expected_hmac_sha256`
- `errors`: list of validation errors

## Example

```bash
python validator.py --payload sample_payload.json --secret 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

## Notes

- The sample payload is only a format example.
- Real cryptographic validity depends on the actual secret key used to sign the payload.
- The supplied hex signature must match the HMAC-SHA256 of the canonical payload string under that secret.
- If the secret is wrong or missing, validation fails.

## Files

- `validator.py` — validation logic and CLI entry point
- `sample_payload.json` — sample payload for testing
