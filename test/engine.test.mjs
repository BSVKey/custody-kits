import test from "node:test";
import assert from "node:assert/strict";
import { genKeypair } from "../lib/keys.mjs";
import { signRecord, contentOf } from "../lib/record.mjs";
import { validateSpec, emptyFile, addRecord, verifyFile, fileFingerprint, specId } from "../src/engine.mjs";

// A kit nobody wrote code for: art shipped from gallery to framer to buyer.
const spec = {
  kind: "bsvkey.kit/1", name: "Artwork transit", slug: "artwork-transit", subject: { label: "Artwork id" }, roles: ["gallery", "framer", "courier", "buyer", "appraiser"],
  records: [
    { id: "release", label: "Release from the gallery", signer: "role:gallery", fields: [{ name: "condition", label: "Condition", type: "select", options: ["perfect", "minor wear", "damaged"], required: true }, { name: "photo", label: "Condition photo", type: "file", required: true }] },
    { id: "receive", label: "Receive it", signer: "receiver", fields: [{ name: "condition", label: "Condition", type: "select", options: ["perfect", "minor wear", "damaged"], required: true }, { name: "note", label: "Note", type: "text" }] },
    { id: "appraise", label: "Appraise", signer: "role:appraiser", fields: [{ name: "valueUsd", label: "Value (USD)", type: "number", required: true }, { name: "report", label: "Report", type: "file" }] },
    { id: "pack", label: "Pack for shipping", signer: "holder", fields: [{ name: "crate", label: "Crate id", type: "text", required: true }] },
  ],
};
const party = (id, role) => ({ id, role, kp: genKeypair() });
const T0 = Date.parse("2026-10-06T00:00:00Z");

function flow() {
  const g = party("gallery-a", "gallery"), f = party("framer-b", "framer"), c = party("courier-c", "courier"), b = party("buyer-d", "buyer"), a = party("appraiser-e", "appraiser");
  const photo = Buffer.from("photo bytes"), report = Buffer.from("appraisal");
  const file = emptyFile(spec, "ART-0042");
  addRecord(spec, file, g, "release", { at: T0, values: { condition: "perfect" }, files: { photo } });
  addRecord(spec, file, f, "receive", { at: T0 + 1, values: { condition: "perfect" } });
  addRecord(spec, file, a, "appraise", { at: T0 + 2, values: { valueUsd: 25000 }, files: { report } });
  addRecord(spec, file, f, "pack", { at: T0 + 3, values: { crate: "CR-9" } });
  addRecord(spec, file, c, "receive", { at: T0 + 4, values: { condition: "perfect" } });
  addRecord(spec, file, b, "receive", { at: T0 + 5, values: { condition: "minor wear", note: "corner scuff" } });
  const keys = [g, f, c, b, a].map((p) => ({ id: p.id, role: p.role, pub: p.kp.pub }));
  return { file, keys, parties: { g, f, c, b, a }, photo, report };
}

test("a valid spec has no problems; bad specs are explained", () => {
  assert.deepEqual(validateSpec(spec), []);
  assert.ok(validateSpec({ ...spec, slug: "Bad Slug" }).some((p) => /slug/.test(p)));
  assert.ok(validateSpec({ ...spec, records: [{ id: "x", label: "X", signer: "boss", fields: [] }] }).some((p) => /signer/.test(p)));
  assert.ok(validateSpec({ ...spec, records: [{ id: "x", label: "X", signer: "anyone", fields: [{ name: "s", type: "select" }] }] }).some((p) => /options/.test(p)));
  assert.notEqual(specId(spec), specId({ ...spec, name: "Other" }));
});

test("a whole flow verifies; custody follows the receivers; files match by fingerprint", () => {
  const { file, keys, photo } = flow();
  const v = verifyFile(spec, file, { keys, files: [{ name: "photo.jpg", bytes: photo }, { name: "fake.jpg", bytes: Buffer.from("x") }] });
  assert.equal(v.ok, true, JSON.stringify(v.problems));
  assert.equal(v.holder, "buyer-d");
  assert.deepEqual(v.trail.map((t) => t.holder), ["gallery-a", "framer-b", "framer-b", "framer-b", "courier-c", "buyer-d"]);
  assert.deepEqual(v.matches.map((m) => [m.name, m.inHistory, m.where[0]?.field]), [["photo.jpg", true, "photo"], ["fake.jpg", false, undefined]]);
  assert.equal(file.records[0].files.photo, fileFingerprint(photo));
});

test("signing rules are enforced when signing", () => {
  const { file, parties } = flow();
  assert.throws(() => addRecord(spec, structuredClone(file), parties.c, "pack", { at: T0 + 9, values: { crate: "x" } }), /only the holder/);
  assert.throws(() => addRecord(spec, structuredClone(file), parties.b, "receive", { at: T0 + 9, values: { condition: "perfect" } }), /already hold/);
  assert.throws(() => addRecord(spec, structuredClone(file), parties.c, "appraise", { at: T0 + 9, values: { valueUsd: 1 } }), /role appraiser/);
  assert.throws(() => addRecord(spec, structuredClone(file), parties.a, "appraise", { at: T0 + 9, values: {} }), /required/);
  assert.throws(() => addRecord(spec, structuredClone(file), parties.f, "receive", { at: T0 + 9, values: { condition: "great" } }), /one of/);
  assert.throws(() => addRecord({ ...spec, name: "Other" }, structuredClone(file), parties.f, "receive", { at: T0 + 9, values: { condition: "perfect" } }), /different kit/);
});

test("tampering is caught by the verifier", () => {
  const { file, keys, parties } = flow();
  const run = (mutate, extra = {}) => { const f = structuredClone(file); mutate(f); return verifyFile(spec, f, { keys, ...extra }).problems.map((p) => p.reason); };
  assert.ok(run((f) => f.records.splice(2, 1)).includes("chain_break"));
  assert.ok(run((f) => { f.records[5].values.condition = "perfect"; }).includes("claimId_mismatch"));
  assert.ok(run((f) => { f.records[5] = signRecord(genKeypair(), contentOf(f.records[5])); }).includes("signer_not_pinned_key"));
  assert.ok(run((f) => { f.records[3] = signRecord(parties.c.kp, { ...contentOf(f.records[3]), by: "courier-c" }); }).includes("signed_by_non_holder"));
  assert.ok(run(() => {}, { keys: keys.map((k) => (k.id === "appraiser-e" ? { ...k, role: "buyer" } : k)) }).includes("signer_lacks_role"));
  assert.ok(run(() => {}, { keys: keys.map((k) => (k.id === "buyer-d" ? { ...k, revokedAt: T0 } : k)) }).includes("key_revoked"));
  assert.ok(run((f) => { f.records[4] = signRecord(parties.c.kp, { ...contentOf(f.records[4]), from: "gallery-a" }); }).includes("receipt_from_wrong_party"));
  const other = verifyFile({ ...spec, name: "Other" }, file, { keys });
  assert.ok(other.problems.some((p) => p.reason === "file_is_for_a_different_kit"));
});
