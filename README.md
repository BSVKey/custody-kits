# Custody Kits

Describe a handoff process once, as a small spec, and get signed custody records and a
verifier for it, without writing code.

Who hands what to whom, who has to sign each step, and what each party records: text,
numbers, dates, choices, and files (fingerprinted, never stored). Every party signs with
its own key, the records chain one after another, and anyone can check the whole history
later without trusting any single party.

Build a kit in the browser, free: https://industries.bsvkey.com/kits/

```
npm test          # offline, zero dependencies
```

## A kit

```json
{
  "kind": "bsvkey.kit/1", "name": "Artwork transit", "slug": "artwork-transit",
  "subject": { "label": "Artwork id" },
  "roles": ["gallery", "framer", "courier", "buyer", "appraiser"],
  "records": [
    { "id": "release", "label": "Release from the gallery", "signer": "role:gallery",
      "fields": [{ "name": "condition", "type": "select", "options": ["perfect", "minor wear", "damaged"], "required": true },
                 { "name": "photo", "type": "file", "required": true }] },
    { "id": "receive", "label": "Receive it", "signer": "receiver",
      "fields": [{ "name": "condition", "type": "select", "options": ["perfect", "minor wear", "damaged"], "required": true }] },
    { "id": "appraise", "label": "Appraise", "signer": "role:appraiser",
      "fields": [{ "name": "valueUsd", "type": "number", "required": true }] }
  ]
}
```

Who may sign a step:

| signer | meaning |
|---|---|
| `receiver` | whoever takes the item signs, and custody moves to them |
| `holder` | only the party holding the item |
| `anyone` | any party with a pinned key |
| `role:<role>` | only a key with that role |

## Use it from code

```js
import { emptyFile, addRecord, verifyFile } from "./src/engine.mjs";
const file = emptyFile(kit, "ART-0042");
addRecord(kit, file, gallery, "release", { at: Date.now(), values: { condition: "perfect" }, files: { photo: bytes } });
addRecord(kit, file, framer, "receive", { at: Date.now(), values: { condition: "perfect" } });
const result = verifyFile(kit, file, { keys: [{ id: "gallery-a", role: "gallery", pub }, ...] });
// result.ok, result.holder, result.trail, result.problems
```

## Rules the verifier applies

- Every record is intact and signed by the pinned key of the party it names; revoked keys
  are refused for records signed after revocation.
- Records chain in order (sequence number and previous id), in time order, for one subject
  and one exact kit (the kit's own fingerprint is in every record).
- Receiver steps must come from the current holder; holder steps only from the holder; role
  steps only from a key with that role.
- Required fields are present and choices are among the allowed options.
- Any file can be checked against the history by its SHA-256 fingerprint.

## Scope

Evidence tooling: it records what each party signed and when. It does not replace the
contracts, inspections or regulatory systems of your industry.

## License

Apache License 2.0. Copyright 2026 Embryo Space Inc. (DBA BSVKey).
