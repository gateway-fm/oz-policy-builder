// A stand-in for the `ozpb` CLI, for check-runner tests only. `FAKE_OZPB_MODE` picks the
// behaviour. Its error output copies the format the check's contract documents: anyhow's
// `Error: ` before the ToolError's `"{code}: {message}"` and one `"\n  - {detail}"` per detail;
// errors that are not ToolErrors print `Error: parsing <path>` with a `Caused by:` block. In `ok`
// mode it answers from `FAKE_OZPB_FIXTURE` and, for prepare-install-intent, echoes the argv and
// the request it read into `next_steps` so the test can see them.
import { readFileSync } from 'node:fs';

const argv = process.argv.slice(2);
const mode = process.env.FAKE_OZPB_MODE;
const fixture = JSON.parse(readFileSync(process.env.FAKE_OZPB_FIXTURE, 'utf8'));
const requestPath = argv[argv.indexOf('--request') + 1];
// The request file's bytes, as the tool would read them: echoed as text, not re-serialized.
const requestText = readFileSync(requestPath, 'utf8');
JSON.parse(requestText);

const fail = (status, text) => {
  process.stderr.write(text);
  process.exit(status);
};
if (mode === 'refuse') {
  fail(1, 'Error: E_DELEGATE_HAS_AUTHORITY: the authority check did not clear this install; there is nothing to sign\n'
    + '  - E_DELEGATE_HAS_AUTHORITY (rule 1): the agent can manage the account Fix: remove it\n'
    + '  - E_UNSUPPORTED_AUTHORITY (rule 2) [classic_multisig]: two signers Fix: use one\n');
}
if (mode === 'unsafe') {
  // The intent's own guard, before any read: a head line and no findings.
  fail(1, 'Error: E_UNSAFE_MANAGEMENT_SURFACE: the new rule targets the account itself, so it would let the agent call the account\'s management methods\n');
}
if (mode === 'parse') {
  fail(1, `Error: parsing ${requestPath}\n\nCaused by:\n    unknown field \`E_NOT_A_CODE\`, expected one of \`spec\`\n`);
}
if (mode === 'usage') fail(2, 'error: unexpected argument \'--nope\' found\n');
if (mode === 'crash') fail(101, 'thread \'main\' panicked\n');
if (mode === 'garbage') {
  process.stdout.write('not json');
  process.exit(0);
}
if (argv[0] === 'prepare-install-intent') {
  fixture.next_steps = [JSON.stringify(argv), requestText];
  process.stdout.write(JSON.stringify(fixture));
} else {
  process.stdout.write(JSON.stringify(fixture.authority));
}
