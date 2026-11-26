// Holds wallet/shared/install-wire.d.mts to the JSON Schemas of the two install tools in
// docs/wire-contract.json, which CI holds to the built server. Field names, which fields
// are required, and their types must match; every definition the schemas use must be declared,
// and nothing else may be. The declarations are parsed by the small reader below, which accepts
// only the subset of TypeScript the file uses and refuses anything else, so a construct it cannot
// read is a failure rather than a declaration it silently skips.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const DECLARATIONS = new URL('../shared/install-wire.d.mts', import.meta.url);
const SNAPSHOT = new URL('../../docs/wire-contract.json', import.meta.url);
const ROOTS = {
  PrepareInstallIntentInput: ['prepare_install_intent', 'inputSchema'],
  PrepareInstallIntentOutput: ['prepare_install_intent', 'outputSchema'],
  AssembleInstallTransactionInput: ['assemble_install_transaction', 'inputSchema'],
  AssembleInstallTransactionOutput: ['assemble_install_transaction', 'outputSchema'],
};
const KEYWORDS = new Set(['string', 'number', 'boolean', 'null', 'unknown']);

// --- the declarations ------------------------------------------------------------------------

function tokens(source) {
  const text = source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ');
  const out = [];
  const pattern = /\s+|([A-Za-z_$][\w$]*)|('[^'\n]*')|([{};:?|[\]<>,=])|(.)/gy;
  for (let match; (match = pattern.exec(text)) && match[0] !== '';) {
    if (match[4]) throw new Error(`install-wire.d.mts: unsupported character ${JSON.stringify(match[4])}`);
    const token = match[1] ?? match[2] ?? match[3];
    if (token) out.push(token);
  }
  return out;
}

function parseDeclarations(source) {
  const list = tokens(source);
  let at = 0;
  const peek = () => list[at];
  const take = (expected) => {
    const token = list[at++];
    if (token === undefined || (expected !== undefined && token !== expected)) {
      throw new Error(`install-wire.d.mts: expected ${expected ?? 'a token'}, found ${token ?? 'the end'}`
        + ` after ${list.slice(Math.max(0, at - 6), at - 1).join(' ')}`);
    }
    return token;
  };
  const name = () => {
    const token = take();
    if (!/^[A-Za-z_]\w*$/.test(token) || KEYWORDS.has(token)) throw new Error(`install-wire.d.mts: ${token} is not a name`);
    return token;
  };
  const object = () => {
    take('{');
    const fields = new Map();
    while (peek() !== '}') {
      if (peek() === 'readonly') take();
      const field = name();
      const optional = peek() === '?';
      if (optional) take();
      take(':');
      if (fields.has(field)) throw new Error(`install-wire.d.mts: ${field} declared twice`);
      fields.set(field, { optional, type: type() });
      if (peek() === ';' || peek() === ',') take();
      else if (peek() !== '}') take(';');
    }
    take('}');
    return { k: 'object', fields };
  };
  const single = () => {
    const token = peek();
    if (token === '{') return object();
    if (token.startsWith("'")) return { k: 'lit', v: take().slice(1, -1) };
    if (KEYWORDS.has(token)) return { k: take() };
    if (token === 'Readonly') {
      take(); take('<'); take('Record'); take('<'); take('string'); take(',');
      const values = type();
      take('>'); take('>');
      return { k: 'map', values };
    }
    return { k: 'ref', name: name() };
  };
  const member = () => {
    const readonlyArray = peek() === 'readonly';
    if (readonlyArray) take();
    let model = single();
    if (peek() === '[') { take('['); take(']'); model = { k: 'array', items: model }; }
    else if (readonlyArray) take('[');
    return model;
  };
  function type() {
    if (peek() === '|') take();
    const members = [member()];
    while (peek() === '|') { take(); members.push(member()); }
    return union(members);
  }
  const declarations = new Map();
  while (at < list.length) {
    take('export');
    const kind = take();
    const declared = name();
    if (declarations.has(declared)) throw new Error(`install-wire.d.mts: ${declared} declared twice`);
    if (kind === 'interface') declarations.set(declared, object());
    else if (kind === 'type') { take('='); declarations.set(declared, type()); take(';'); }
    else throw new Error(`install-wire.d.mts: export ${kind} is not a type declaration`);
  }
  return declarations;
}

// --- the schemas -----------------------------------------------------------------------------

function union(members) {
  const flat = members.flatMap((member) => (member.k === 'union' ? member.of : [member]));
  const seen = new Map(flat.map((member) => [key(member), member]));
  return seen.size === 1 ? [...seen.values()][0] : { k: 'union', of: [...seen.values()] };
}

// Keywords that annotate or bound a value without changing its shape. Every other keyword must be
// one a shape below reads, so a schema that says more than the reader understands (an `allOf`, a
// `const` beside an `enum`, extra properties beside fixed ones) is refused, never half-read.
const ANNOTATIONS = new Set(['description', 'title', 'format', 'minimum', 'maximum', '$schema']);

/**
 * The shape a schema states. What the reader cannot read is reported once, through `refuse`, and
 * becomes an `unread` shape the comparison passes over, so one refusal is one message rather than
 * every comparison that would have depended on it.
 */
function fromSchema(schema, where, refuse) {
  const unreadable = (why) => { refuse(`${where}: ${why}`); return { k: 'unread' }; };
  if (schema === true) return { k: 'unknown' };
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) return unreadable('not a schema');
  const extra = (...read) => Object.keys(schema).filter((k) => !ANNOTATIONS.has(k) && !read.includes(k));
  const reads = (...read) => {
    const others = extra(...read);
    return others.length ? unreadable(`the drift reader does not read ${others.join(', ')}: ${JSON.stringify(schema)}`) : null;
  };
  const literal = (v) => (v === null ? { k: 'null' } : { k: 'lit', v });
  if (schema.$ref !== undefined) {
    const match = /^#\/\$defs\/(\w+)$/.exec(schema.$ref);
    return reads('$ref') ?? (match ? { k: 'ref', name: match[1] } : unreadable(`unsupported $ref ${schema.$ref}`));
  }
  for (const branching of ['oneOf', 'anyOf']) {
    if (schema[branching] !== undefined) {
      return reads(branching) ?? union(schema[branching].map((branch, i) => fromSchema(branch, `${where}|${i}`, refuse)));
    }
  }
  // A sibling `type` must admit every literal: one it does not is a value the schema refuses although
  // the literals list it, so the pair is refused rather than read as the literals alone.
  const jsonTypes = (v) => (v === null ? ['null'] : Array.isArray(v) ? ['array'] : typeof v === 'number'
    ? (Number.isInteger(v) ? ['integer', 'number'] : ['number']) : [typeof v]);
  const typed = (values) => {
    if (schema.type === undefined) return null;
    const types = [schema.type].flat();
    const stray = values.filter((v) => !jsonTypes(v).some((t) => types.includes(t)));
    return stray.length ? unreadable(`${JSON.stringify(stray)} beside type ${JSON.stringify(schema.type)}: ${JSON.stringify(schema)}`) : null;
  };
  if (schema.const !== undefined) return reads('const', 'type') ?? typed([schema.const]) ?? literal(schema.const);
  if (schema.enum !== undefined) return reads('enum', 'type') ?? typed(schema.enum) ?? union(schema.enum.map(literal));
  if (Array.isArray(schema.type)) return union(schema.type.map((t) => fromSchema({ ...schema, type: t }, where, refuse)));
  switch (schema.type) {
    case 'string': case 'boolean': case 'null': return reads('type') ?? { k: schema.type };
    case 'integer': case 'number': return reads('type') ?? { k: 'number' };
    case 'array': return reads('type', 'items') ?? { k: 'array', items: fromSchema(schema.items, `${where}[]`, refuse) };
    case 'object': {
      if (schema.properties !== undefined) {
        // Fixed properties, closed or not; a schema for further properties would be a map beside them.
        const refused = reads('type', 'properties', 'required', 'additionalProperties');
        if (refused) return refused;
        if (![undefined, false, true].includes(schema.additionalProperties)) {
          return unreadable(`properties beside a schema for further ones: ${JSON.stringify(schema)}`);
        }
        const required = new Set(schema.required ?? []);
        const undefinedRequired = [...required].filter((field) => !(field in schema.properties));
        if (undefinedRequired.length) return unreadable(`requires ${undefinedRequired.join(', ')}, which it does not define`);
        return { k: 'object', fields: new Map(Object.entries(schema.properties).map(([field, value]) =>
          [field, { optional: !required.has(field), type: fromSchema(value, `${where}.${field}`, refuse) }])) };
      }
      if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        return reads('type', 'additionalProperties') ?? { k: 'map', values: fromSchema(schema.additionalProperties, `${where}{}`, refuse) };
      }
      break;
    }
    default:
  }
  return unreadable(`the drift reader does not cover this schema: ${JSON.stringify(schema)}`);
}

function key(model) {
  switch (model.k) {
    case 'lit': return JSON.stringify(model.v);
    case 'ref': return model.name;
    case 'array': return `${key(model.items)}[]`;
    case 'map': return `Record<string, ${key(model.values)}>`;
    case 'object': return `{ ${[...model.fields].sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([field, { optional, type }]) => `${field}${optional ? '?' : ''}: ${key(type)}`).join('; ')} }`;
    case 'union': return model.of.map(key).sort().join(' | ');
    default: return model.k;
  }
}

// --- the comparison --------------------------------------------------------------------------

/**
 * Every way the declarations differ from the two tools' schemas; empty when they match. Each
 * root is compared within its own tool schema: a `$ref` resolves in that schema's `$defs` only,
 * since that is where a client reading that schema resolves it.
 */
function drift(source, contract) {
  const errors = [];
  const refuse = (message) => errors.push(message);
  let declared;
  try { declared = parseDeclarations(source); } catch (error) { return [error.message]; }
  const tools = new Map(contract.tools.map((tool) => [tool.name, tool]));
  const used = new Set();
  const variants = (model) => (model.k === 'object'
    ? [...model.fields].filter(([, field]) => field.type.k === 'lit').map(([f, { type }]) => `${f}=${type.v}`).sort().join(',')
    : null);

  for (const [root, [tool, field]] of Object.entries(ROOTS)) {
    const schema = tools.get(tool)?.[field];
    used.add(root);
    if (!schema) { errors.push(`${root}: ${tool} has no ${field} in the snapshot`); continue; }
    const { $defs: local = {}, ...top } = schema;
    const shapes = new Map();
    const compared = new Set();
    const definition = (name, where) => {
      if (compared.has(name)) return;
      compared.add(name);
      used.add(name);
      if (!Object.hasOwn(local, name)) { errors.push(`${where}: $ref #/$defs/${name} dangles: ${tool} ${field} defines no ${name}`); return; }
      if (!declared.has(name)) { errors.push(`${where}: the schema defines ${name}; install-wire.d.mts does not declare it`); return; }
      if (!shapes.has(name)) shapes.set(name, fromSchema(local[name], name, refuse));
      compare(declared.get(name), shapes.get(name), name);
    };
    function compare(ts, want, where) {
      if (want.k === 'unread') return;
      if (ts.k === 'ref' && want.k === 'ref') {
        if (ts.name !== want.name) errors.push(`${where}: declared ${ts.name}, the schema has ${want.name}`);
        else definition(ts.name, where);
        return;
      }
      if (ts.k !== want.k) { errors.push(`${where}: declared ${key(ts)}, the schema has ${key(want)}`); return; }
      switch (ts.k) {
        case 'object': {
          for (const [name, wanted] of want.fields) {
            const have = ts.fields.get(name);
            if (!have) { errors.push(`${where}.${name}: in the schema (${wanted.optional ? 'optional' : 'required'}), not declared`); continue; }
            if (have.optional !== wanted.optional) {
              errors.push(`${where}.${name}: declared ${have.optional ? 'optional' : 'required'}, the schema has it ${wanted.optional ? 'optional' : 'required'}`);
            }
            compare(have.type, wanted.type, `${where}.${name}`);
          }
          for (const name of ts.fields.keys()) if (!want.fields.has(name)) errors.push(`${where}.${name}: declared, not in the schema`);
          return;
        }
        case 'array': compare(ts.items, want.items, `${where}[]`); return;
        case 'map': compare(ts.values, want.values, `${where}{}`); return;
        case 'union': {
          const wanted = new Map(want.of.map((member) => [key(member), member]));
          const have = new Map(ts.of.map((member) => [key(member), member]));
          // An identical member still names definitions (its own, or inside a variant) to compare.
          for (const [k, member] of have) if (wanted.has(k)) { compare(member, wanted.get(k), where); wanted.delete(k); have.delete(k); }
          // A variant that matches by its literal tag but differs inside is compared field by field.
          for (const [k, member] of [...have]) {
            const tag = variants(member);
            const pair = tag && [...wanted].find(([, other]) => variants(other) === tag);
            if (pair) { compare(member, pair[1], `${where}<${tag}>`); have.delete(k); wanted.delete(pair[0]); }
          }
          if ([...wanted.values()].some((member) => member.k === 'unread')) return;
          for (const k of wanted.keys()) errors.push(`${where}: the schema allows ${k}, not declared`);
          for (const k of have.keys()) errors.push(`${where}: declared ${k}, not in the schema`);
          return;
        }
        default:
          if (key(ts) !== key(want)) errors.push(`${where}: declared ${key(ts)}, the schema has ${key(want)}`);
      }
    }
    let ts = declared.get(root);
    // A root may be declared as an alias of the definition it is (the intent's request is the
    // authority check's request); the schema states that root inline.
    while (ts?.k === 'ref' && declared.has(ts.name)) { used.add(ts.name); ts = declared.get(ts.name); }
    if (!ts) { errors.push(`${root}: not declared in install-wire.d.mts`); continue; }
    compare(ts, fromSchema(top, root, refuse), root);
  }
  for (const name of declared.keys()) {
    if (!used.has(name)) errors.push(`${name}: declared in install-wire.d.mts, used by neither tool's schemas`);
  }
  // A definition several tools carry is compared once per tool; say each difference once.
  return [...new Set(errors)];
}

// --- tests -----------------------------------------------------------------------------------

const declarations = () => readFileSync(DECLARATIONS, 'utf8');
const snapshot = () => JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
const toolSchema = (contract, tool, field) => contract.tools.find((t) => t.name === tool)[field];

test('the typed install surface matches the committed wire contract', () => {
  const errors = drift(declarations(), snapshot());
  assert.deepEqual(errors, [], 'wallet/shared/install-wire.d.mts no longer matches docs/wire-contract.json, '
    + 'which is regenerated from the server (docs/VERSIONING.md#keeping-the-snapshot-current). '
    + `Update the declarations to the schema:\n  ${errors.join('\n  ')}`);
});

test('every definition the two tools use is declared, and is compared', () => {
  const contract = snapshot();
  const names = new Set(Object.keys(ROOTS));
  for (const [tool, field] of Object.values(ROOTS)) {
    for (const name of Object.keys(toolSchema(contract, tool, field).$defs ?? {})) names.add(name);
  }
  // The four roots and all 34 definitions they reach, with nothing the reader could skip.
  assert.ok(names.size >= 30, `only ${names.size} names: the snapshot lost the install schemas`);
  const declared = parseDeclarations(declarations());
  for (const name of names) assert.ok(declared.has(name), `${name} is not declared`);
});

const mutations = {
  'a renamed request field': [(c) => {
    const schema = toolSchema(c, 'assemble_install_transaction', 'inputSchema');
    schema.properties.payer = schema.properties.fee_payer;
    delete schema.properties.fee_payer;
    schema.required = schema.required.map((f) => (f === 'fee_payer' ? 'payer' : f));
  }, /AssembleInstallTransactionInput\.payer: in the schema[\s\S]*AssembleInstallTransactionInput\.fee_payer: declared, not in the schema/],
  'a required field made optional': [(c) => {
    const schema = toolSchema(c, 'prepare_install_intent', 'outputSchema');
    schema.required = schema.required.filter((f) => f !== 'next_steps');
  }, /PrepareInstallIntentOutput\.next_steps: declared required, the schema has it optional/],
  'a nullable field made non-null': [(c) => {
    toolSchema(c, 'prepare_install_intent', 'outputSchema').properties.valid_until_ledger.type = 'integer';
  }, /PrepareInstallIntentOutput\.valid_until_ledger: declared null \| number, the schema has number/],
  'a changed field type in a definition': [(c) => {
    for (const [tool, field] of Object.values(ROOTS)) {
      const def = toolSchema(c, tool, field).$defs?.PolicyClassicSigner;
      if (def) def.properties.weight = { type: 'string' };
    }
  }, /PolicyClassicSigner\.weight: declared number, the schema has string/],
  'a new error code': [(c) => {
    for (const [tool, field] of Object.values(ROOTS)) {
      const def = toolSchema(c, tool, field).$defs?.ErrorCode;
      if (def) def.oneOf.push({ type: 'string', const: 'E_NEWLY_ADDED' });
    }
  }, /ErrorCode: the schema allows "E_NEWLY_ADDED", not declared/],
  'a new variant field': [(c) => {
    for (const [tool, field] of Object.values(ROOTS)) {
      const def = toolSchema(c, tool, field).$defs?.PolicySignerKey;
      if (def) { def.oneOf[0].properties.label = { type: 'string' }; def.oneOf[0].required.push('label'); }
    }
  }, /PolicySignerKey<kind=delegated>\.label: in the schema \(required\), not declared/],
  'a definition the declarations lack': [(c) => {
    const schema = toolSchema(c, 'assemble_install_transaction', 'outputSchema');
    schema.properties.restoration = { $ref: '#/$defs/RestorationPlan' };
    schema.$defs.RestorationPlan = { type: 'string', enum: ['none'] };
  }, /AssembleInstallTransactionOutput\.restoration: declared InstallAssemblyRestoration, the schema has RestorationPlan/],
};

for (const [name, [mutate, expected]] of Object.entries(mutations)) {
  test(`the drift check fails on ${name}`, () => {
    const contract = snapshot();
    mutate(contract);
    const errors = drift(declarations(), contract);
    assert.notDeepEqual(errors, []);
    assert.match(errors.join('\n'), expected);
  });
}

// Each of these adds something the reader does not model; read as before, each would pass.
const unreadable = {
  'properties beside a oneOf (a flattened enum)': ['InstallPolicyParams', (def) => {
    Object.assign(def, { type: 'object', properties: { extra: { type: 'string' } }, required: ['extra'] });
  }],
  'an allOf': ['PolicyClassicSigner', (def) => { def.allOf = [{ properties: { extra: { type: 'string' } }, required: ['extra'] }]; }],
  'a schema for further properties (a flattened map)': ['PolicyClassicSigner', (def) => {
    def.additionalProperties = { type: 'integer' };
  }],
  'a const beside an enum': ['PolicyKeyScheme', (def) => { def.const = 'ed25519'; }],
  'a oneOf beside an anyOf': ['PolicyRecognition', (def) => { def.anyOf = [{ type: 'string' }]; }],
  'a required name with no property': ['PolicyClassicSigner', (def) => { def.required = [...def.required, 'label']; }],
};
for (const [name, [definition, mutate]] of Object.entries(unreadable)) {
  test(`the drift check refuses ${name}`, () => {
    const contract = snapshot();
    let changed = 0;
    for (const [tool, field] of Object.values(ROOTS)) {
      const def = toolSchema(contract, tool, field).$defs?.[definition];
      if (def) { mutate(def); changed += 1; }
    }
    assert.ok(changed > 0, `no schema defines ${definition}`);
    // One refusal, said once: what depends on the unread definition is not reported again.
    const errors = drift(declarations(), contract);
    assert.equal(errors.length, 1, errors.join('\n'));
    assert.match(errors[0], /does not read|beside a schema for further|requires label/);
  });
}
test('the drift check refuses prefixItems on an array', () => {
  const contract = snapshot();
  toolSchema(contract, 'assemble_install_transaction', 'outputSchema').properties.wallet_requirements.prefixItems = [{ type: 'integer' }];
  const errors = drift(declarations(), contract);
  assert.equal(errors.length, 1, errors.join('\n'));
  assert.match(errors[0], /does not read prefixItems/);
});

test('a $ref resolves in its own tool schema only, and a missing definition is a dangling $ref', () => {
  // Another tool's schema still defines PolicyClassicSigner; pooled definitions would hide this.
  const contract = snapshot();
  delete toolSchema(contract, 'assemble_install_transaction', 'outputSchema').$defs.PolicyClassicSigner;
  assert.deepEqual(drift(declarations(), contract), [
    'PolicyClassicAccount.signers[]: $ref #/$defs/PolicyClassicSigner dangles: '
      + 'assemble_install_transaction outputSchema defines no PolicyClassicSigner',
  ]);
});

test('a definition changed in one tool schema only is a difference in that schema', () => {
  const contract = snapshot();
  toolSchema(contract, 'prepare_install_intent', 'outputSchema').$defs.PolicyClassicSigner.properties.weight = { type: 'string' };
  assert.deepEqual(drift(declarations(), contract), ['PolicyClassicSigner.weight: declared number, the schema has string']);
});

test('a null in an enum is the null type, which `| null` declares', () => {
  const contract = snapshot();
  for (const [tool, field] of Object.values(ROOTS)) {
    const def = toolSchema(contract, tool, field).$defs?.PolicyVerifierObservation;
    if (def) def.properties.scheme = { type: ['string', 'null'], enum: ['ed25519', 'webauthn_p256', null] };
  }
  const errors = drift(declarations().replace('readonly scheme: PolicyKeyScheme | null;',
    "readonly scheme: 'ed25519' | 'webauthn_p256' | null;"), contract);
  assert.deepEqual(errors.filter((e) => e.startsWith('PolicyVerifierObservation.scheme')), []);
});

test('a const or enum literal its sibling type does not admit is refused, not read as the literal', () => {
  // The nullable enum above with `type` narrowed to a string: the schema now refuses null, which the literals still list.
  const nonNullable = snapshot();
  for (const [tool, field] of Object.values(ROOTS)) {
    const def = toolSchema(nonNullable, tool, field).$defs?.PolicyVerifierObservation;
    if (def) def.properties.scheme = { type: 'string', enum: ['ed25519', 'webauthn_p256', null] };
  }
  const errors = drift(declarations().replace('readonly scheme: PolicyKeyScheme | null;',
    "readonly scheme: 'ed25519' | 'webauthn_p256' | null;"), nonNullable);
  assert.equal(errors.length, 1, errors.join('\n'));
  assert.match(errors[0], /^PolicyVerifierObservation\.scheme: \[null\] beside type "string"/);
  // A const whose type admits no string.
  const integer = snapshot();
  toolSchema(integer, 'assemble_install_transaction', 'outputSchema').$defs.InstallAssemblyRestoration.oneOf[2].type = 'integer';
  const constErrors = drift(declarations(), integer);
  assert.equal(constErrors.length, 1, constErrors.join('\n'));
  assert.match(constErrors[0], /^InstallAssemblyRestoration\|2: \["automatic_within_invocation"\] beside type "integer"/);
});

test('a literal\'s JSON type is checked against `type`, a string or a list, an integer being a number too', () => {
  const read = (schema) => { const refused = []; const model = fromSchema(schema, 'x', (m) => refused.push(m)); return { model, refused }; };
  for (const schema of [{ type: 'number', const: 1 }, { type: 'integer', const: 2 }, { type: ['string', 'null'], const: null },
    { type: 'boolean', enum: [true, false] }, { type: ['integer', 'string'], enum: [1, 'a'] }]) {
    assert.deepEqual(read(schema).refused, [], JSON.stringify(schema));
  }
  for (const schema of [{ type: 'integer', const: 1.5 }, { type: 'string', const: null }, { type: 'string', enum: ['a', true] },
    { type: ['string', 'null'], enum: ['a', 1] }]) {
    const { model, refused } = read(schema);
    assert.equal(model.k, 'unread', JSON.stringify(schema));
    assert.equal(refused.length, 1, JSON.stringify(schema));
  }
});

test('the drift check fails on a declaration no schema uses, and on syntax it cannot read', () => {
  assert.match(drift(`${declarations()}\nexport type Stray = string;\n`, snapshot()).join('\n'),
    /Stray: declared in install-wire\.d\.mts, used by neither tool's schemas/);
  const unreadable = declarations().replace('readonly next_steps: readonly string[];', 'readonly next_steps: Array<string>;');
  assert.notEqual(unreadable, declarations());
  assert.match(drift(unreadable, snapshot()).join('\n'), /install-wire\.d\.mts: expected/);
});
