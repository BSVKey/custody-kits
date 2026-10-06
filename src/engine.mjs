// Custody Kits: describe a handoff process once, as a small spec, and get signed records and a
// verifier for it without writing code. The same primitives as every BSVKey custody core:
// canonical JSON, SHA-256 content ids, Ed25519 signatures, records chained one after another.
//
// A kit spec:
//   {
//     kind: "bsvkey.kit/1", name, slug,
//     subject: { label },                      what one working file tracks, e.g. "Pallet id"
//     roles: ["grower", "packer", ...],        optional; keys carry a role
//     records: [{
//       id, label,
//       signer: "receiver" | "holder" | "anyone" | "role:<role>",
//         receiver   the signer takes custody (records where it came from)
//         holder     only the party holding the item may sign it
//         anyone     any pinned key
//         role:x     a key with role x
//       fields: [{ name, label, type: "text" | "number" | "datetime" | "select" | "file", options?, required? }],
//     }],
//   }
//
// A working file: { kind: "bsvkey.kit-file/1", kit: slug, specId, subject, records: [...] }.
// Each record: { kind: "kit.<slug>.<id>/1", kit, specId, subject, seq, prev, type, by, from?, at,
//                values, files }, signed by `by`. `files` holds SHA-256 fingerprints only.
import { createHash } from "node:crypto";
import { canonicalize } from "../lib/canonical.mjs";
import { signRecord, verifyRecord } from "../lib/record.mjs";

const SLUG = /^[a-z0-9][a-z0-9-]{1,39}$/;
const NAME = /^[A-Za-z][A-Za-z0-9_]{0,39}$/;
const TYPES = new Set(["text", "number", "datetime", "select", "file"]);
const SIGNERS = /^(receiver|holder|anyone|role:[A-Za-z0-9 _-]{1,40})$/;
export const fileFingerprint = (bytes) => "0x" + createHash("sha256").update(bytes).digest("hex");
export const specId = (spec) => "0x" + createHash("sha256").update(canonicalize(spec)).digest("hex");

// Check a spec is complete and safe to use; returns the list of problems (empty = valid).
export function validateSpec(spec) {
  const p = [];
  if (!spec || spec.kind !== "bsvkey.kit/1") return ["not a kit spec (kind must be bsvkey.kit/1)"];
  if (!spec.name || String(spec.name).length > 80) p.push("name is required (up to 80 characters)");
  if (!SLUG.test(spec.slug || "")) p.push("slug must be 2 to 40 lowercase letters, digits or dashes");
  if (!spec.subject?.label) p.push("subject.label is required, e.g. Pallet id");
  if (!Array.isArray(spec.records) || !spec.records.length || spec.records.length > 20) p.push("1 to 20 record types");
  const ids = new Set();
  for (const r of spec.records || []) {
    if (!NAME.test(r.id || "")) p.push(`record id "${r.id}" must be letters, digits or _`);
    if (ids.has(r.id)) p.push(`record id "${r.id}" is used twice`);
    ids.add(r.id);
    if (!r.label) p.push(`record ${r.id}: label is required`);
    if (!SIGNERS.test(r.signer || "")) p.push(`record ${r.id}: signer must be receiver, holder, anyone or role:<role>`);
    if (String(r.signer).startsWith("role:") && spec.roles && !spec.roles.includes(r.signer.slice(5))) p.push(`record ${r.id}: role ${r.signer.slice(5)} is not in roles`);
    const names = new Set();
    for (const f of r.fields || []) {
      if (!NAME.test(f.name || "")) p.push(`record ${r.id}: field name "${f.name}" must be letters, digits or _`);
      if (names.has(f.name)) p.push(`record ${r.id}: field ${f.name} is used twice`);
      names.add(f.name);
      if (!TYPES.has(f.type)) p.push(`record ${r.id}: field ${f.name} has unknown type ${f.type}`);
      if (f.type === "select" && (!Array.isArray(f.options) || !f.options.length)) p.push(`record ${r.id}: select field ${f.name} needs options`);
    }
    if ((r.fields || []).length > 30) p.push(`record ${r.id}: at most 30 fields`);
  }
  return p;
}

export const emptyFile = (spec, subject) => ({ kind: "bsvkey.kit-file/1", kit: spec.slug, specId: specId(spec), subject, records: [] });

// Who holds the subject after these records: the last receiver.
export function holderOf(spec, records) {
  let holder = null;
  for (const r of records) if (spec.records.find((t) => t.id === r.type)?.signer === "receiver" || holder === null) holder = r.by;
  return holder;
}

// Sign the next record into a working file. key: { id, role?, kp }. values: field -> value;
// files: field -> bytes (fingerprinted here; the bytes are not stored).
export function addRecord(spec, file, key, typeId, { at, values = {}, files = {} }) {
  const t = spec.records.find((x) => x.id === typeId);
  if (!t) throw new Error(`unknown record type ${typeId}`);
  if (file.specId !== specId(spec)) throw new Error("this working file belongs to a different kit");
  const holder = holderOf(spec, file.records);
  if (t.signer === "holder" && holder !== null && holder !== key.id) throw new Error(`only the holder (${holder}) can sign ${t.label}`);
  if (t.signer === "receiver" && holder === key.id) throw new Error("you already hold it");
  if (t.signer.startsWith("role:") && key.role !== t.signer.slice(5)) throw new Error(`${t.label} needs a key with role ${t.signer.slice(5)}`);
  const v = {}, fp = {};
  for (const f of t.fields || []) {
    if (f.type === "file") { if (files[f.name]) fp[f.name] = fileFingerprint(files[f.name]); else if (f.required) throw new Error(`${f.label || f.name}: choose a file`); continue; }
    const x = values[f.name];
    if (x === undefined || x === null || x === "") { if (f.required) throw new Error(`${f.label || f.name} is required`); continue; }
    if (f.type === "number" && !Number.isFinite(Number(x))) throw new Error(`${f.label || f.name} must be a number`);
    if (f.type === "select" && !f.options.includes(x)) throw new Error(`${f.label || f.name} must be one of ${f.options.join(", ")}`);
    v[f.name] = f.type === "number" || f.type === "datetime" ? Number(x) : String(x).slice(0, 2000);
  }
  const last = file.records.at(-1);
  file.records.push(signRecord(key.kp, {
    kind: `kit.${spec.slug}.${t.id}/1`, kit: spec.slug, specId: file.specId, subject: file.subject, seq: file.records.length, prev: last ? last.claimId : null,
    type: t.id, by: key.id, from: t.signer === "receiver" ? holder : null, at, values: v, files: fp,
  }));
  return file;
}

// Verify a working file against the kit and the pinned public keys [{ id, pub, role?, revokedAt? }].
// files: optional [{ name, bytes }] to match against the fingerprints in the records.
export function verifyFile(spec, file, { keys, files = [] }) {
  const problems = [];
  const bad = (reason, detail = {}) => problems.push({ reason, ...detail });
  const sp = validateSpec(spec);
  if (sp.length) return { ok: false, problems: sp.map((x) => ({ reason: "spec_invalid", detail: x })), trail: [], holder: null, matches: [] };
  const sid = specId(spec);
  if (file?.specId !== sid) bad("file_is_for_a_different_kit");
  const byId = new Map(keys.map((k) => [k.id, k]));
  const trail = [];
  let holder = null;
  (file?.records || []).forEach((r, i) => {
    const v = verifyRecord(r);
    if (!v.ok) { bad(v.reason, { seq: i }); return; }
    const t = spec.records.find((x) => x.id === r.type);
    if (!t || r.kind !== `kit.${spec.slug}.${t.id}/1`) { bad("unknown_record_type", { seq: i, type: r.type }); return; }
    const k = byId.get(r.by);
    if (!k) bad("signer_not_pinned", { seq: i, by: r.by });
    else if (k.pub !== v.signer) bad("signer_not_pinned_key", { seq: i, by: r.by });
    else if (k.revokedAt !== undefined && r.at >= k.revokedAt) bad("key_revoked", { seq: i, by: r.by });
    if (r.specId !== sid || r.subject !== file.subject) bad("record_for_another_subject_or_kit", { seq: i });
    if (r.seq !== i || r.prev !== (i ? file.records[i - 1].claimId : null)) bad("chain_break", { seq: i });
    if (i && r.at < file.records[i - 1].at) bad("time_regression", { seq: i });
    if (t.signer === "holder" && holder !== null && r.by !== holder) bad("signed_by_non_holder", { seq: i, by: r.by, holder });
    if (t.signer === "receiver") { if (r.from !== holder) bad("receipt_from_wrong_party", { seq: i, from: r.from, holder }); }
    if (t.signer.startsWith("role:") && k && k.role !== t.signer.slice(5)) bad("signer_lacks_role", { seq: i, by: r.by, role: t.signer.slice(5) });
    for (const f of t.fields || []) {
      const present = f.type === "file" ? r.files?.[f.name] : r.values?.[f.name];
      if (f.required && (present === undefined || present === "")) bad("required_field_missing", { seq: i, field: f.name });
      if (f.type === "select" && present !== undefined && !f.options.includes(present)) bad("value_not_allowed", { seq: i, field: f.name });
    }
    if (t.signer === "receiver" || holder === null) holder = r.by;
    trail.push({ seq: i, at: r.at, type: t.id, label: t.label, by: r.by, from: r.from, holder, values: r.values, files: r.files });
  });
  const matches = files.map((f) => {
    const fp = fileFingerprint(f.bytes);
    const hit = (file?.records || []).flatMap((r) => Object.entries(r.files || {}).filter(([, x]) => x === fp).map(([field]) => ({ seq: r.seq, type: r.type, field })));
    return { name: f.name, fingerprint: fp, inHistory: hit.length > 0, where: hit };
  });
  return { ok: problems.length === 0, problems, trail, holder, subject: file?.subject ?? null, matches };
}
