import http from 'k6/http';
import { sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { sessionAllowed } from './contracts.mjs';

const mapping = JSON.parse(open('./restaurant-items.json'));
const restaurants = Object.keys(mapping);
const trackingExperiences = JSON.parse(open(__ENV.FIXTURE_FILE));
const site = 'https://qr.gilgaamesh.com';
const supabaseUrl = 'https://supabase.gilgaamesh.com';
const anonKey = __ENV.ANON_KEY;
if (!anonKey || trackingExperiences.length !== 10 || !restaurants.length) throw new Error('Benchmark fixture configuration is incomplete');
const peak = Number(__ENV.PEAK_VUS || 10);
const hold = Number(__ENV.DURATION_SECONDS || 60);
const nodeIndex = Number(__ENV.NODE_INDEX || 1);
const headers = { 'Content-Type': 'application/json', apikey: anonKey, Authorization: `Bearer ${anonKey}` };
const gameKeys = ['tetris', 'breakout_arkanoid', 'snake', 'air_hockey'];
const errors = new Rate('errors');
const journeys = new Rate('journey_success');
const trackingAdmission = new Rate('tracking_admission_success');
const gameAdmission = new Rate('game_admission_success');
const assets = new Rate('asset_success');
const analyticsDelivery = new Rate('analytics_delivery_success');
const edgeHitMenu = new Rate('menu_edge_hit');
const edgeHitAssets = new Rate('asset_edge_hit');
const menuLatency = new Trend('menu_read_duration', true);
const trackingLatency = new Trend('tracking_session_duration', true);
const assetLatency = new Trend('tracking_asset_duration', true);
const gameLatency = new Trend('game_session_duration', true);
const analyticsAccepted = new Counter('analytics_accepted');
const analyticsRateLimited = new Counter('menu_analytics_rate_limited');
const functionRateLimited = new Counter('function_rate_limited');
const functionUnavailable = new Counter('function_unavailable');
const functionTransportErrors = new Counter('function_transport_errors');

export const options = {
  scenarios: { workload: { executor: 'ramping-vus', startVUs: 0, stages: [
    { duration: '15s', target: peak }, { duration: `${hold}s`, target: peak }, { duration: '10s', target: 0 },
  ], gracefulRampDown: '10s', gracefulStop: '10s' } },
  thresholds: {
    http_req_failed: ['rate<0.01'], errors: ['rate<0.01'], journey_success: ['rate>0.99'],
    tracking_admission_success: ['rate>0.99'], game_admission_success: ['rate>0.99'],
    asset_success: ['rate>0.99'], analytics_delivery_success: ['rate>0.99'],
    menu_read_duration: ['p(95)<1000'], tracking_session_duration: ['p(95)<2500'],
    tracking_asset_duration: ['p(95)<1000'], game_session_duration: ['p(95)<2500'],
  },
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};
function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0; return (c === 'x' ? r : (r & 3) | 8).toString(16);
  });
}
function body(response) { try { return response.json(); } catch { return null; } }
function checked(ok, metric) { errors.add(!ok); if (metric) metric.add(ok); return ok; }
function post(slug, payload) {
  const response = http.post(`${supabaseUrl}/functions/v1/${slug}`, JSON.stringify(payload), { headers, timeout: '15s', tags: { name: slug } });
  functionRateLimited.add(response.status === 429 ? 1 : 0);
  functionUnavailable.add(response.status >= 500 ? 1 : 0);
  functionTransportErrors.add(response.status === 0 ? 1 : 0);
  return response;
}
function asset(url) {
  // Capabilities may only be sent to the configured site or backend origin.
  if (typeof url !== 'string' || !(url.startsWith(site + '/') || url.startsWith(supabaseUrl + '/'))) return checked(false, assets);
  const res = http.get(url, { timeout: '20s', redirects: 0, tags: { name: 'protected-asset' } });
  edgeHitAssets.add((res.headers['X-Ar-Asset-Cache'] ?? res.headers['x-ar-asset-cache']) === 'HIT');
  assetLatency.add(res.timings.duration);
  return checked(res.status === 200 && res.body?.length > 0, assets);
}
function menuEvent(restaurant, item) {
  const event = { id: uuid(), event_type: item ? 'live_preview_open' : 'menu_open', restaurant_id: restaurant };
  if (item) event.item_id = item;
  const res = http.post(site + '/api/analytics/events', JSON.stringify({ events: [event] }), {
    headers: { 'Content-Type': 'application/json', Origin: site }, timeout: '15s', tags: { name: 'menu-analytics' },
  });
  const ok = checked(res.status === 202 && body(res)?.accepted === 1, analyticsDelivery);
  analyticsRateLimited.add(res.status === 429 ? 1 : 0);
  if (ok) analyticsAccepted.add(1);
  return ok;
}
export default function () {
  let ok = true;
  const roll = Math.random();
  if (roll < 0.60) {
    const restaurant = restaurants[Math.floor(Math.random() * restaurants.length)];
    const page = http.get(`${site}/menu/${restaurant}`, { timeout: '15s', tags: { name: 'menu-page' } });
    ok = checked(page.status === 200) && ok;
    const menu = http.get(`${site}/api/public-menu/${restaurant}`, { timeout: '15s', tags: { name: 'public-menu' } });
    edgeHitMenu.add((menu.headers['Cf-Cache-Status'] ?? menu.headers['CF-Cache-Status']) === 'HIT');
    menuLatency.add(menu.timings.duration);
    ok = checked(menu.status === 200 && body(menu) !== null) && ok;
    ok = menuEvent(restaurant) && ok;
    const items = mapping[restaurant];
    if (items.length && Math.random() < 0.4) ok = menuEvent(restaurant, items[Math.floor(Math.random() * items.length)]) && ok;
  } else if (roll < 0.85) {
    const exp = trackingExperiences[Math.floor(Math.random() * trackingExperiences.length)];
    const res = post('image-tracking-session', { token: exp.token });
    trackingLatency.add(res.timings.duration);
    const data = body(res);
    ok = checked(sessionAllowed(res.status, data), trackingAdmission);
    if (ok) {
      ok = asset(data.target?.image_url) && ok;
      ok = asset(data.content?.glb_url || data.content?.url) && ok;
      const events = ['camera_started', 'target_first_detected', 'content_started'].map(event_type => ({ id: uuid(), event_type }));
      const ev = post('image-tracking-event', { session_token: data.session_token, events });
      const delivered = checked((ev.status === 200 || ev.status === 202) && body(ev)?.success === true && body(ev)?.accepted === events.length, analyticsDelivery);
      if (delivered) analyticsAccepted.add(events.length);
      ok = delivered && ok;
    }
  } else {
    const gameKey = gameKeys[Math.floor(Math.random() * gameKeys.length)];
    const res = post('entertainment-session', { game_key: gameKey, action: 'start' });
    gameLatency.add(res.timings.duration);
    const data = body(res);
    ok = checked(sessionAllowed(res.status, data), gameAdmission);
    if (ok) {
      const xr = http.get(site + '/external/xr/v-c4781db3f6e5f3ec8285/xr.js', { timeout: '15s', tags: { name: 'xr-engine' } });
      ok = checked(xr.status === 200 && xr.body?.length > 0) && ok;
      const end = post('entertainment-session', { game_key: gameKey, session_token: data.session_token, action: 'end' });
      ok = checked(end.status === 200 && body(end)?.success === true) && ok;
    }
  }
  journeys.add(ok);
  // Ten simulated visitors share each runner IP. Respect the public 100-event
  // per-minute IP limit rather than treating expected anti-abuse denials as capacity.
  sleep(5 + Math.random() * 3);
}
export function handleSummary(data) {
  data.meta = { node_index: nodeIndex, run_id: __ENV.RUN_ID, configured_vus: peak,
    duration_ms: data.state.testRunDurationMs, finished_at: new Date().toISOString() };
  return { [`summary-node-${nodeIndex}.json`]: JSON.stringify(data, null, 2) };
}
