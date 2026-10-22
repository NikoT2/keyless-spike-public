// Signature check plus design 3.4's claim rules, with no node: imports, so verify-card.mjs (node/bun) and
// worker/worker.mjs (a Cloudflare Worker) run the same code. Returns a report with the decoded card; never the card.
import { errors, jwtVerify } from 'jose';
import {
  CLOCK_TOLERANCE_SECONDS,
  checkClaims,
  checkManifest,
  decodeUnverified,
  GITHUB_ISSUER,
  MAX_TOKEN_AGE_SECONDS,
  PINNED_WORKFLOW_PATH,
  sha256Hex,
} from './card-checks.mjs';

export async function verifyCardWith(card, { signInOrigin, workflowPath = PINNED_WORKFLOW_PATH, keySet, at, manifestBytes }) {
  if (!signInOrigin) throw new Error('signInOrigin is required');
  const { header, payload: unverifiedPayload } = decodeUnverified(card);
  const signature = { ok: false, alg: header.alg, kid: header.kid, asOf: (at ?? new Date()).toISOString() };
  let payload = unverifiedPayload;
  try {
    const verified = await jwtVerify(card, keySet, {
      issuer: GITHUB_ISSUER,
      algorithms: ['RS256'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      maxTokenAge: MAX_TOKEN_AGE_SECONDS,
      ...(at ? { currentDate: at } : {}),
    });
    payload = verified.payload;
    signature.ok = true;
  } catch (error) {
    signature.error = error instanceof errors.JOSEError ? `${error.code}: ${error.message}` : String(error);
  }

  const claims = checkClaims(payload, { signInOrigin, workflowPath });
  const manifest =
    manifestBytes === undefined ? undefined : checkManifest(manifestBytes, await sha256Hex(manifestBytes), claims.facts);
  const reason = !signature.ok ? 'card-invalid' : (claims.reason ?? manifest?.reason);
  return {
    verdict: reason ? 'refused' : 'accepted',
    reason,
    signature,
    header: { alg: header.alg, kid: header.kid, typ: header.typ, x5t: header.x5t },
    rules: claims.rules,
    facts: claims.facts,
    ...(manifest ? { manifest } : {}),
    claims: payload,
  };
}
