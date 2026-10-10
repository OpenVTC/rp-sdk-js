/**
 * A small JSON Schema (2020-12) validator for the keywords the `auth/oob`
 * and framework schemas use, so tests can check emitted documents against
 * the published schemas without adding a validator dependency.
 *
 * The schemas are copied into `test/fixtures/trust-tasks` (see its SOURCE).
 * `format` is checked for `date-time` and `uri` only.
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type Schema = Record<string, unknown>;

const ROOT = fileURLToPath(
  new URL("../fixtures/trust-tasks/specs/", import.meta.url),
);
const cache = new Map<string, Schema>();

function load(file: string): Schema {
  let s = cache.get(file);
  if (!s) {
    s = JSON.parse(readFileSync(file, "utf8")) as Schema;
    cache.set(file, s);
  }
  return s;
}

function pointer(root: Schema, ptr: string): Schema {
  let cur: unknown = root;
  for (const part of ptr.split("/").filter(Boolean)) {
    cur = (cur as Record<string, unknown>)[
      part.replace(/~1/g, "/").replace(/~0/g, "~")
    ];
    if (cur === undefined) throw new Error(`bad pointer ${ptr}`);
  }
  return cur as Schema;
}

function deref(
  ref: string,
  file: string,
  root: Schema,
): { schema: Schema; file: string; root: Schema } {
  const [path, frag = ""] = ref.split("#");
  const f = path ? resolve(dirname(file), path) : file;
  const r = path ? load(f) : root;
  return { schema: frag ? pointer(r, frag) : r, file: f, root: r };
}

function check(
  v: unknown,
  s: Schema,
  file: string,
  root: Schema,
  at: string,
  errs: string[],
): void {
  if (typeof s.$ref === "string") {
    const d = deref(s.$ref, file, root);
    check(v, d.schema, d.file, d.root, at, errs);
  }
  const err = (m: string) => errs.push(`${at || "/"}: ${m}`);
  if (s.type !== undefined) {
    const types = Array.isArray(s.type) ? s.type : [s.type];
    const ok = types.some((t) =>
      t === "integer"
        ? Number.isInteger(v)
        : t === "array"
          ? Array.isArray(v)
          : t === "object"
            ? v !== null && typeof v === "object" && !Array.isArray(v)
            : t === "null"
              ? v === null
              : typeof v === t,
    );
    if (!ok)
      return err(`expected ${types.join("|")}, got ${JSON.stringify(v)}`);
  }
  if (s.const !== undefined && JSON.stringify(v) !== JSON.stringify(s.const))
    err(`expected const ${JSON.stringify(s.const)}`);
  if (
    Array.isArray(s.enum) &&
    !s.enum.some((e) => JSON.stringify(e) === JSON.stringify(v))
  )
    err(`not in enum ${JSON.stringify(s.enum)}`);
  if (Array.isArray(s.oneOf)) {
    const n = s.oneOf.filter((sub) => {
      const e: string[] = [];
      check(v, sub as Schema, file, root, at, e);
      return e.length === 0;
    }).length;
    if (n !== 1) err(`matches ${n} oneOf branches`);
  }
  if (typeof v === "string") {
    if (typeof s.minLength === "number" && [...v].length < s.minLength)
      err(`shorter than ${s.minLength}`);
    if (typeof s.maxLength === "number" && [...v].length > s.maxLength)
      err(`longer than ${s.maxLength}`);
    if (typeof s.pattern === "string" && !new RegExp(s.pattern, "u").test(v))
      err(`does not match ${s.pattern}`);
    if (
      s.format === "date-time" &&
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(
        v,
      )
    )
      err("not a date-time");
    if (s.format === "uri" && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(v))
      err("not a uri");
  }
  if (typeof v === "number" && typeof s.minimum === "number" && v < s.minimum)
    err(`below ${s.minimum}`);
  if (Array.isArray(v)) {
    if (typeof s.minItems === "number" && v.length < s.minItems)
      err(`fewer than ${s.minItems} items`);
    if (
      s.uniqueItems === true &&
      new Set(v.map((x) => JSON.stringify(x))).size !== v.length
    )
      err("items not unique");
    if (s.items && typeof s.items === "object")
      v.forEach((x, i) =>
        check(x, s.items as Schema, file, root, `${at}/${i}`, errs),
      );
  }
  if (v !== null && typeof v === "object" && !Array.isArray(v)) {
    const o = v as Record<string, unknown>;
    const props = (s.properties ?? {}) as Record<string, Schema>;
    for (const r of (s.required ?? []) as string[])
      if (!(r in o)) err(`missing ${r}`);
    if (
      typeof s.minProperties === "number" &&
      Object.keys(o).length < s.minProperties
    )
      err(`fewer than ${s.minProperties} members`);
    const dep = (s.dependentRequired ?? {}) as Record<string, string[]>;
    for (const [k, reqs] of Object.entries(dep))
      if (k in o)
        for (const r of reqs) if (!(r in o)) err(`${k} requires ${r}`);
    for (const [k, val] of Object.entries(o)) {
      if (props[k]) check(val, props[k], file, root, `${at}/${k}`, errs);
      else if (s.additionalProperties === false) err(`unexpected member ${k}`);
      else if (
        s.additionalProperties &&
        typeof s.additionalProperties === "object"
      ) {
        check(
          val,
          s.additionalProperties as Schema,
          file,
          root,
          `${at}/${k}`,
          errs,
        );
      }
      if (s.propertyNames && typeof s.propertyNames === "object")
        check(
          k,
          s.propertyNames as Schema,
          file,
          root,
          `${at}/${k}(name)`,
          errs,
        );
    }
  }
}

function validate(v: unknown, file: string, ptr = ""): string[] {
  const root = load(file);
  const errs: string[] = [];
  check(v, ptr ? pointer(root, ptr) : root, file, root, "", errs);
  return errs;
}

const taskFile = (task: string) =>
  join(ROOT, "auth/oob", task, "0.1/payload.schema.json");

/** Errors from validating a full request document: envelope plus payload. */
export function validateRequestDocument(task: string, doc: unknown): string[] {
  return [
    ...validate(doc, join(ROOT, "_framework/0.4/trust-task.schema.json")),
    ...validate((doc as { payload?: unknown }).payload, taskFile(task)).map(
      (e) => `payload${e}`,
    ),
  ];
}

/** Errors from validating a `#response` document: envelope plus response payload. */
export function validateResponseDocument(task: string, doc: unknown): string[] {
  return [
    ...validate(doc, join(ROOT, "_framework/0.4/trust-task.schema.json")),
    ...validate(
      (doc as { payload?: unknown }).payload,
      taskFile(task),
      "/$defs/Response",
    ).map((e) => `payload${e}`),
  ];
}
