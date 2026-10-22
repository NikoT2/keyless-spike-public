#!/usr/bin/env node
// Checks one GitHub Actions identity card (OIDC token) the way design 3.4 says Conloca will: signature against
// GitHub's key list (jose, RS256 only, exact issuer, 60 s clock tolerance, 10 min max age), then every claim rule.
// Prints a JSON report with the decoded header and claims. It never prints the card itself.
//
//   node verify-card.mjs --card-file card.jwt --sign-in-origin https://app.staging.conloca.com \
//     [--workflow-path .github/workflows/conloca-editor.yml] [--manifest manifest.json] \
//     [--jwks-url URL | --jwks-file keys.json] [--at <unix seconds>] [--out report.json]
//   ... --card-env NAME reads the card from an environment variable instead of a file.
//
// Exit 0 = accepted, 1 = refused (report still written), 2 = usage error. Works under bun and node >= 20.
import { readFileSync, writeFileSync } from 'node:fs';
import { createLocalJWKSet, createRemoteJWKSet } from 'jose';
import { GITHUB_JWKS_URL } from './card-checks.mjs';
import { verifyCardWith } from './card-verify.mjs';

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error(`bad argument near ${key ?? '(end)'}`);
    args[key.slice(2)] = value;
  }
  return args;
}

// One key-list reader per process (per Worker instance in the server), so jose's cache and cooldown apply.
let remoteKeys;
function keySetFor(args) {
  if (args['jwks-file']) return createLocalJWKSet(JSON.parse(readFileSync(args['jwks-file'], 'utf8')));
  remoteKeys ??= createRemoteJWKSet(new URL(args['jwks-url'] ?? GITHUB_JWKS_URL));
  return remoteKeys;
}

/** The command line's options as a call (the self-test uses this). */
export function verifyCard(card, args) {
  return verifyCardWith(card, {
    signInOrigin: args['sign-in-origin'],
    workflowPath: args['workflow-path'],
    keySet: keySetFor(args),
    at: args.at === undefined ? undefined : new Date(Number(args.at) * 1000),
    manifestBytes: args.manifest ? readFileSync(args.manifest) : undefined,
  });
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(String(error));
    process.exit(2);
  }
  const card = (args['card-file'] ? readFileSync(args['card-file'], 'utf8') : (process.env[args['card-env'] ?? ''] ?? ''))
    .trim();
  if (!card) {
    console.error('no card: pass --card-file or --card-env');
    process.exit(2);
  }
  const report = await verifyCard(card, args);
  const text = `${JSON.stringify(report, null, 2)}\n`;
  if (args.out) writeFileSync(args.out, text);
  process.stdout.write(text);
  process.exit(report.verdict === 'accepted' ? 0 : 1);
}

if (process.argv[1]?.endsWith('verify-card.mjs')) await main();
