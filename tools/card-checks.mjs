// Claim checks for a GitHub Actions identity card (OIDC token) presented to Conloca's editor-upload route.
// Mirrors design section 3.4 steps 1-3 and 5 (step 4, the workspace lookup, needs the server and is reported as the
// lookup keys only). Pure functions, no I/O: verify-card.mjs does the signature check and calls checkClaims().
// Runs under bun, node >= 20 and a Cloudflare Worker (no node: imports).

export const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';
export const GITHUB_JWKS_URL = `${GITHUB_ISSUER}/.well-known/jwks`;
export const PINNED_WORKFLOW_PATH = '.github/workflows/conloca-editor.yml';
export const CLOCK_TOLERANCE_SECONDS = 60;
export const MAX_TOKEN_AGE_SECONDS = 600;
export const ALLOWED_EVENTS = ['push', 'workflow_dispatch'];

const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;

/** The same strict decimal test the org tracker applies to stored repository ids. */
export function isStrictDecimalId(value) {
  if (typeof value !== 'string') return false;
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 && String(n) === value;
}

/** `<sign-in origin>/editor-files/sha256:` + 64 lowercase hex; returns the hash or null. */
export function audienceHash(aud, signInOrigin) {
  const prefix = `${signInOrigin.replace(/\/+$/, '')}/editor-files/sha256:`;
  const values = Array.isArray(aud) ? aud : [aud];
  // GitHub sends one audience as a plain string; a list of several is refused (one card, one upload).
  if (values.length !== 1 || typeof values[0] !== 'string' || !values[0].startsWith(prefix)) return null;
  const hash = values[0].slice(prefix.length);
  return HEX64.test(hash) ? hash : null;
}

/**
 * Every rule from design 3.4 step 3, evaluated (not short-circuited) so a spike record shows each one.
 * `workflowPath` is the pinned path; the claims printer passes its own path to see the rest of the rules pass.
 */
export function checkClaims(payload, { signInOrigin, workflowPath = PINNED_WORKFLOW_PATH }) {
  const rules = [];
  const rule = (name, ok, reason, detail) => rules.push({ name, ok: Boolean(ok), reason, detail });

  rule('iss', payload.iss === GITHUB_ISSUER, 'card-invalid', `iss=${JSON.stringify(payload.iss)}`);
  const hash = audienceHash(payload.aud, signInOrigin);
  rule('aud', hash !== null, 'wrong-environment', `aud=${JSON.stringify(payload.aud)}`);
  rule(
    'event_name',
    ALLOWED_EVENTS.includes(payload.event_name),
    'event-not-allowed',
    `event_name=${JSON.stringify(payload.event_name)}`,
  );
  const ref = typeof payload.ref === 'string' ? payload.ref : '';
  rule(
    'ref',
    payload.ref_type === 'branch' && ref.startsWith('refs/heads/') && ref.length > 'refs/heads/'.length,
    'not-a-branch',
    `ref_type=${JSON.stringify(payload.ref_type)} ref=${JSON.stringify(payload.ref)}`,
  );
  rule(
    'runner_environment',
    payload.runner_environment === 'github-hosted',
    'self-hosted-runner',
    `runner_environment=${JSON.stringify(payload.runner_environment)}`,
  );
  const expectedWorkflowRef =
    typeof payload.repository === 'string' ? `${payload.repository}/${workflowPath}@${ref}` : undefined;
  rule(
    'workflow_ref',
    expectedWorkflowRef !== undefined && payload.workflow_ref === expectedWorkflowRef,
    'workflow-not-pinned',
    `workflow_ref=${JSON.stringify(payload.workflow_ref)} expected=${JSON.stringify(expectedWorkflowRef)}`,
  );
  rule(
    'job_workflow_ref',
    typeof payload.job_workflow_ref === 'string' && payload.job_workflow_ref === payload.workflow_ref,
    'workflow-not-pinned',
    `job_workflow_ref=${JSON.stringify(payload.job_workflow_ref)}`,
  );
  rule(
    'repository_id',
    isStrictDecimalId(payload.repository_id),
    'card-invalid',
    `repository_id=${JSON.stringify(payload.repository_id)}`,
  );
  rule(
    'repository_owner_id',
    isStrictDecimalId(payload.repository_owner_id),
    'card-invalid',
    `repository_owner_id=${JSON.stringify(payload.repository_owner_id)}`,
  );
  const commit = typeof payload.sha === 'string' ? payload.sha : payload.workflow_sha;
  rule(
    'sha',
    typeof commit === 'string' && HEX40.test(commit),
    'card-invalid',
    `sha=${JSON.stringify(payload.sha)} workflow_sha=${JSON.stringify(payload.workflow_sha)}`,
  );
  rule(
    'jti/exp/iat',
    typeof payload.jti === 'string' &&
      payload.jti.length > 0 &&
      Number.isInteger(payload.exp) &&
      Number.isInteger(payload.iat),
    'card-invalid',
    `jti=${payload.jti ? 'present' : 'missing'} exp=${payload.exp} iat=${payload.iat}`,
  );

  const firstFailure = rules.find((r) => !r.ok);
  return {
    ok: firstFailure === undefined,
    reason: firstFailure?.reason,
    rules,
    facts: {
      audienceHash: hash,
      branch: ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : null,
      commit: typeof commit === 'string' ? commit : null,
      commitSource: typeof payload.sha === 'string' ? 'sha' : 'workflow_sha',
      shaEqualsWorkflowSha: payload.sha === payload.workflow_sha,
      // Step 4 needs the server: these are the two keys it routes on.
      workspaceLookup: { repository_owner_id: payload.repository_owner_id, repository_id: payload.repository_id },
      lifetimeSeconds: Number.isInteger(payload.exp) && Number.isInteger(payload.iat) ? payload.exp - payload.iat : null,
      notBeforeSkewSeconds:
        Number.isInteger(payload.nbf) && Number.isInteger(payload.iat) ? payload.iat - payload.nbf : null,
      provenance: {
        run_id: payload.run_id,
        run_attempt: payload.run_attempt,
        actor_id: payload.actor_id,
        ref_protected: payload.ref_protected,
        event_name: payload.event_name,
        workflow_ref: payload.workflow_ref,
      },
    },
  };
}

/**
 * Design 3.4 step 5 for the manifest alone: its SHA-256 equals the audience hash, and its commit and branch equal
 * the card's. (Per-file checks need the multipart body and belong to the server stub.)
 */
export function checkManifest(manifestBytes, manifestHash, facts) {
  const problems = [];
  if (manifestHash !== facts.audienceHash) problems.push(`manifest sha256 ${manifestHash} != aud ${facts.audienceHash}`);
  let manifest;
  try {
    manifest = JSON.parse(new TextDecoder().decode(manifestBytes));
  } catch {
    problems.push('manifest is not JSON');
  }
  if (manifest && 'commit' in manifest && manifest.commit !== facts.commit) {
    problems.push(`manifest.commit ${manifest.commit} != card ${facts.commit}`);
  }
  if (manifest && 'branch' in manifest && manifest.branch !== facts.branch) {
    problems.push(`manifest.branch ${manifest.branch} != card ${facts.branch}`);
  }
  return { ok: problems.length === 0, reason: problems.length ? 'upload-mismatch' : undefined, problems };
}

/** Header and payload of a compact JWT, without checking anything. Never returns the signature. */
export function decodeUnverified(card) {
  const parts = card.split('.');
  if (parts.length !== 3) throw new Error('not a compact JWT');
  const json = (part) => {
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((part.length + 3) % 4);
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))));
  };
  return { header: json(parts[0]), payload: json(parts[1]) };
}

/** Lowercase hex SHA-256 with Web Crypto, so the same code runs in node, bun and a Worker. */
export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
