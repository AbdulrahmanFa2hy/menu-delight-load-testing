const allowedHolds = [30, 60, 120, 300];
const allowedModes = ['mixed', 'tracking', 'games'];

/** Reserve asset invocations without uploading a Cloudflare account credential.
 * This estimate includes fastest think time, full ramp exposure, one finishing
 * journey per VU, 32 probe requests and 25% headroom; it is not a billing meter.
 */
export function workersBudget({total, hold, mode, budget = 0, verifiedAt = '', now = Date.now()}) {
  if (!Number.isInteger(total) || total < 100 || total > 10000 ||
      !allowedHolds.includes(hold) || !allowedModes.includes(mode) ||
      !Number.isSafeInteger(budget) || budget < 0)
    throw new Error('Invalid Workers request-budget configuration');
  const trackingFraction = mode === 'tracking' ? 1 : mode === 'mixed' ? 0.25 : 0;
  const required = trackingFraction === 0 ? 0 : Math.ceil(
    (trackingFraction * 2 / 5 * total * (hold + 15 + 10) + 2 * total + 32) * 1.25);
  if (budget < required)
    throw new Error(`Need a verified Workers request budget of at least ${required}; provided ${budget}. Check account-wide usage and reserve normal traffic before dispatch. Origin backend diagnostics still use the public asset Worker.`);
  if (required > 0) {
    const timestamp = Date.parse(verifiedAt);
    const format = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
    const end = now + (120 + 15 + hold + 10 + 90) * 1000;
    const canonical = Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : '';
    const normalized = verifiedAt.includes('.') ? verifiedAt : verifiedAt.replace('Z', '.000Z');
    if (!format.test(verifiedAt) || !Number.isFinite(timestamp) || normalized !== canonical || timestamp > now ||
        now - timestamp > 15 * 60 * 1000 ||
        new Date(timestamp).toISOString().slice(0, 10) !== new Date(now).toISOString().slice(0, 10) ||
        new Date(end).toISOString().slice(0, 10) !== new Date(now).toISOString().slice(0, 10))
      throw new Error('Workers budget verification must be a UTC timestamp from the last 15 minutes, on this UTC day; dispatch after the quota reset if the planned run crosses midnight UTC.');
  }
  return {required_requests: required, available_request_budget: budget,
    verified_at: required > 0 ? verifiedAt : null, estimate_headroom_percent: 25,
    asset_worker_exercised: required > 0};
}
