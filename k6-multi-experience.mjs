import http from 'k6/http';
import { sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Load distributed benchmark data
const mapping = JSON.parse(open('./restaurant-items.json'));
const restaurants = Object.keys(mapping);
const trackingExperiences = JSON.parse(open('./tracking-experiences.json'));

const site = __ENV.SITE_URL || 'https://qr.gilgaamesh.com';
const supabaseUrl = __ENV.SUPABASE_URL || 'https://supabase.gilgaamesh.com';
const anonKey = __ENV.ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlneGR4ZW5iaXd1bHVjb2t2c3J1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDkyMzY2NDUsImV4cCI6MjA2NDgxMjY0NX0.9lqR9YdD7uB9C7tF5xG3vK2mJ8wP4qS6tU1zX0yA3bE';
const peak = Number(__ENV.PEAK_VUS || 1000);
const hold = Number(__ENV.DURATION_SECONDS || 60);
const nodeIndex = __ENV.NODE_INDEX || '1';

// Custom Metrics
const errors = new Rate('errors');
const edgeHitMenu = new Rate('menu_edge_hit');
const edgeHitAssets = new Rate('asset_edge_hit');
const menuLatency = new Trend('menu_read_duration', true);
const trackingLatency = new Trend('tracking_session_duration', true);
const assetLatency = new Trend('tracking_asset_duration', true);
const gameLatency = new Trend('game_session_duration', true);
const analyticsAccepted = new Counter('analytics_accepted');

const gameKeys = ['tetris', 'breakout_arkanoid', 'snake', 'air_hockey'];

export const options = {
  discardResponseBodies: false,
  scenarios: {
    node_workload: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '15s', target: peak },
        { duration: `${hold}s`, target: peak },
        { duration: '10s', target: 0 },
      ],
      gracefulRampDown: '10s',
      gracefulStop: '10s',
    },
  },
  thresholds: {
    errors: ['rate<0.05'],
    menu_read_duration: ['p(95)<1000'],
    tracking_session_duration: ['p(95)<2500'],
    tracking_asset_duration: ['p(95)<1000'],
  },
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 3) | 8).toString(16);
  });
}

export default function () {
  const commonHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  };

  const roll = Math.random();

  // 1. (60%) Restaurant Public Menu
  if (roll < 0.60) {
    const restaurant = restaurants[Math.floor(Math.random() * restaurants.length)];
    const items = mapping[restaurant] || [];

    http.get(`${site}/menu/${restaurant}`, { headers: commonHeaders, timeout: '15s' });

    const menuRes = http.get(`${site}/api/public-menu/${restaurant}`, {
      headers: { ...commonHeaders, Accept: 'application/json' },
      timeout: '15s',
    });
    const cfStatus = menuRes.headers['Cf-Cache-Status'] ?? menuRes.headers['CF-Cache-Status'];
    edgeHitMenu.add(cfStatus === 'HIT');
    menuLatency.add(menuRes.timings.duration);
    errors.add(menuRes.status !== 200);

    const eventHeaders = { ...commonHeaders, 'Content-Type': 'application/json', Origin: site };
    const openRes = http.post(
      `${site}/api/analytics/events`,
      JSON.stringify({ events: [{ id: uuid(), event_type: 'menu_open', restaurant_id: restaurant }] }),
      { headers: eventHeaders, timeout: '15s' }
    );
    if (openRes.status === 202) analyticsAccepted.add(1);
    errors.add(openRes.status !== 202);

    if (items.length && Math.random() < 0.40) {
      const prevRes = http.post(
        `${site}/api/analytics/events`,
        JSON.stringify({
          events: [{
            id: uuid(), event_type: 'live_preview_open', restaurant_id: restaurant,
            item_id: items[Math.floor(Math.random() * items.length)],
          }],
        }),
        { headers: eventHeaders, timeout: '15s' }
      );
      if (prevRes.status === 202) analyticsAccepted.add(1);
    }
  }

  // 2. (25%) Image Tracking AR Experience
  else if (roll < 0.85 && trackingExperiences.length > 0) {
    const exp = trackingExperiences[Math.floor(Math.random() * trackingExperiences.length)];
    const edgeHeaders = {
      ...commonHeaders,
      'Content-Type': 'application/json',
      apikey: anonKey,
      Authorization: `Bearer ${anonKey}`,
    };

    const sessRes = http.post(
      `${supabaseUrl}/functions/v1/image-tracking-session`,
      JSON.stringify({ token: exp.token }),
      { headers: edgeHeaders, timeout: '15s' }
    );
    trackingLatency.add(sessRes.timings.duration);
    const sessOk = sessRes.status === 200;
    errors.add(!sessOk);

    if (sessOk && sessRes.body) {
      let data;
      try { data = JSON.parse(sessRes.body); } catch (_) {}
      if (data && data.status === 'allowed') {
        if (data.target?.image_url) {
          const tRes = http.get(data.target.image_url, { headers: commonHeaders, timeout: '20s' });
          const hit = (tRes.headers['X-Ar-Asset-Cache'] ?? tRes.headers['x-ar-asset-cache']) === 'HIT';
          edgeHitAssets.add(hit);
          assetLatency.add(tRes.timings.duration);
        }
        const cUrl = data.content?.glb_url || data.content?.url;
        if (cUrl) {
          const cRes = http.get(cUrl, { headers: commonHeaders, timeout: '20s' });
          const hit = (cRes.headers['X-Ar-Asset-Cache'] ?? cRes.headers['x-ar-asset-cache']) === 'HIT';
          edgeHitAssets.add(hit);
          assetLatency.add(cRes.timings.duration);
        }
        if (data.session_token) {
          const evRes = http.post(
            `${supabaseUrl}/functions/v1/image-tracking-event`,
            JSON.stringify({
              session_token: data.session_token,
              events: [
                { id: uuid(), event_type: 'camera_started' },
                { id: uuid(), event_type: 'target_first_detected' },
                { id: uuid(), event_type: 'content_started' },
              ],
            }),
            { headers: edgeHeaders, timeout: '15s' }
          );
          if (evRes.status === 202) analyticsAccepted.add(3);
          errors.add(evRes.status !== 202);
        }
      }
    }
  }

  // 3. (15%) Arcade Games
  else {
    const gameKey = gameKeys[Math.floor(Math.random() * gameKeys.length)];
    const edgeHeaders = {
      ...commonHeaders,
      'Content-Type': 'application/json',
      apikey: anonKey,
      Authorization: `Bearer ${anonKey}`,
    };

    const startRes = http.post(
      `${supabaseUrl}/functions/v1/entertainment-session`,
      JSON.stringify({ game_key: gameKey, action: 'start' }),
      { headers: edgeHeaders, timeout: '15s' }
    );
    gameLatency.add(startRes.timings.duration);
    const startOk = startRes.status === 200;
    errors.add(!startOk);

    if (startOk && startRes.body) {
      let gData;
      try { gData = JSON.parse(startRes.body); } catch (_) {}
      if (gData && gData.status === 'allowed' && gData.session_token) {
        analyticsAccepted.add(1);

        http.get(`${site}/external/xr/v-c4781db3f6e5f3ec8285/xr.js`, { headers: commonHeaders, timeout: '15s' });

        const endRes = http.post(
          `${supabaseUrl}/functions/v1/entertainment-session`,
          JSON.stringify({ game_key: gameKey, session_token: gData.session_token, action: 'end' }),
          { headers: edgeHeaders, timeout: '15s' }
        );
        if (endRes.status === 200) analyticsAccepted.add(1);
      }
    }
  }

  sleep(1.5 + Math.random() * 1.5);
}

export function handleSummary(data) {
  const reqs = data.metrics.http_reqs ? data.metrics.http_reqs.values.count : 0;
  const rate = data.metrics.http_reqs ? data.metrics.http_reqs.values.rate.toFixed(1) : 0;
  const failRate = data.metrics.errors ? (data.metrics.errors.values.rate * 100).toFixed(2) : 0;
  const p95Menu = data.metrics.menu_read_duration && data.metrics.menu_read_duration.values['p(95)']
    ? `${data.metrics.menu_read_duration.values['p(95)'].toFixed(1)}ms` : 'N/A';
  const p95Track = data.metrics.tracking_session_duration && data.metrics.tracking_session_duration.values['p(95)']
    ? `${data.metrics.tracking_session_duration.values['p(95)'].toFixed(1)}ms` : 'N/A';
  const p95Asset = data.metrics.tracking_asset_duration && data.metrics.tracking_asset_duration.values['p(95)']
    ? `${data.metrics.tracking_asset_duration.values['p(95)'].toFixed(1)}ms` : 'N/A';
  const p95Game = data.metrics.game_session_duration && data.metrics.game_session_duration.values['p(95)']
    ? `${data.metrics.game_session_duration.values['p(95)'].toFixed(1)}ms` : 'N/A';
  const cfMenu = data.metrics.menu_edge_hit ? `${(data.metrics.menu_edge_hit.values.rate * 100).toFixed(1)}%` : 'N/A';
  const cfAsset = data.metrics.asset_edge_hit ? `${(data.metrics.asset_edge_hit.values.rate * 100).toFixed(1)}%` : 'N/A';

  console.log(`\n==================================================`);
  console.log(`🚀 [NODE ${nodeIndex}] LOAD TEST SUMMARY REPORT`);
  console.log(`==================================================`);
  console.log(`Total Requests Completed : ${reqs} (${rate} req/s)`);
  console.log(`Error Rate               : ${failRate}%`);
  console.log(`Public Menu P95 Latency  : ${p95Menu} (CF Hit: ${cfMenu})`);
  console.log(`Tracking AR P95 Latency  : ${p95Track}`);
  console.log(`AR Assets P95 Latency    : ${p95Asset} (CF Hit: ${cfAsset})`);
  console.log(`Arcade Game P95 Latency  : ${p95Game}`);
  console.log(`==================================================\n`);

  return {
    [`summary-node-${nodeIndex}.json`]: JSON.stringify(data, null, 2),
  };
}
