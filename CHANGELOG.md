## Unreleased

- Deleting or updating a record now deletes the records Spaceship returned for that
  name and type instead of a body rebuilt from octoDNS' record. Spaceship matches a
  DELETE exactly and answers 200 when nothing matches: CNAME values are stored with a
  trailing dot, a set can hold the same value twice, and records carry extra fields.
  Such deletes silently did nothing, the next plan showed the same changes again, and
  an update failed with "CNAME with host ... already exists".
- Before creating CNAME/ALIAS records the zone is read again: an identical record is
  left alone, a different one of the same name is deleted first.
- The TTL of a record that is deleted is no longer clamped to 60-3600.
- SRV records map Spaceship's service/protocol fields; TXT semicolons are escaped.
- ALIAS records are supported.
- tests/test_spaceship_apply.py runs the apply logic against a fake Spaceship API.

## v0.0.1: initial version

It works well enough for me but tests are missing.
