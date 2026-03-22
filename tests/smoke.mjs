import assert from 'node:assert/strict';
import {
  decryptPayload,
  encryptPayload,
  expandNodes,
  extractLatestTimestampFromContent,
  extractPreferredEndpointsFromContent,
  parseNodeLinks,
  parsePreferredEndpoints,
  renderClashSubscription,
  renderRawSubscription,
  renderSurgeSubscription,
} from '../src/core.js';
import { runScheduledRefresh } from '../src/worker.js';

const CARRIER_TELECOM = '\u7535\u4fe1';
const CARRIER_UNICOM = '\u8054\u901a';
const CARRIER_MOBILE = '\u79fb\u52a8';

const vmess =
  'vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJkZW1vLXdzLXRscyIsCiAgImFkZCI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAicG9ydCI6ICI0NDMiLAogICJpZCI6ICIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLAogICJzY3kiOiAiYXV0byIsCiAgIm5ldCI6ICJ3cyIsCiAgInRscyI6ICJ0bHMiLAogICJwYXRoIjogIi93cyIsCiAgImhvc3QiOiAiZWRnZS5leGFtcGxlLmNvbSIsCiAgInNuaSI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAiZnAiOiAiY2hyb21lIiwKICAiYWxwbiI6ICJoMixodHRwLzEuMSIKfQ==';

const { nodes } = parseNodeLinks(vmess);
assert.equal(nodes.length, 1);
assert.equal(nodes[0].type, 'vmess');
assert.equal(nodes[0].server, 'edge.example.com');

const { endpoints } = parsePreferredEndpoints('104.16.1.2#HK\n104.17.2.3:2053#US');
assert.equal(endpoints.length, 2);

const expanded = expandNodes(nodes, endpoints, { keepOriginalHost: true, namePrefix: 'CF' });
assert.equal(expanded.nodes.length, 2);
assert.equal(expanded.nodes[0].server, '104.16.1.2');
assert.equal(expanded.nodes[0].hostHeader, 'edge.example.com');
assert.equal(expanded.nodes[1].port, 2053);
assert.match(expanded.nodes[0].name, /CF/);
assert.match(expanded.nodes[0].name, /HK/);

const remoteJson = extractPreferredEndpointsFromContent(
  JSON.stringify({
    data: [
      { ip: '104.16.10.1', carrier: CARRIER_TELECOM },
      { ip: '104.17.20.2', carrier: CARRIER_UNICOM },
      { ip: '104.18.30.3', carrier: CARRIER_MOBILE },
    ],
  }),
  {
    defaultPort: 443,
    carrierFilters: `${CARRIER_TELECOM},${CARRIER_MOBILE}`,
    maxEndpoints: 2,
    contentType: 'application/json',
  },
);
assert.equal(remoteJson.parser, 'json');
assert.equal(remoteJson.endpoints.length, 2);
assert.equal(remoteJson.endpoints[0].label, `${CARRIER_TELECOM}-01`);
assert.equal(remoteJson.endpoints[1].label, `${CARRIER_MOBILE}-01`);

const remoteText = extractPreferredEndpointsFromContent(
  `${CARRIER_TELECOM} 104.16.11.1\n${CARRIER_UNICOM} 104.17.21.2\n${CARRIER_MOBILE} 104.18.31.3`,
  {
    defaultPort: 443,
    carrierFilters: `${CARRIER_TELECOM},${CARRIER_MOBILE}`,
    maxEndpoints: 2,
  },
);
assert.equal(remoteText.parser, 'text');
assert.equal(remoteText.endpoints.length, 2);
assert.equal(remoteText.endpoints[0].label, `${CARRIER_TELECOM}-01`);
assert.equal(remoteText.endpoints[1].label, `${CARRIER_MOBILE}-01`);

const remoteHtml = extractPreferredEndpointsFromContent(
  `
  <table>
    <tr><td>telecom</td><td>104.16.12.1</td></tr>
    <tr><td>unicom</td><td>104.17.22.2</td></tr>
    <tr><td>mobile</td><td>104.18.32.3</td></tr>
  </table>
  `,
  {
    defaultPort: 443,
    carrierFilters: `${CARRIER_TELECOM},${CARRIER_MOBILE}`,
    maxEndpoints: 2,
  },
);
assert.equal(remoteHtml.parser, 'html');
assert.equal(remoteHtml.endpoints.length, 2);
assert.equal(remoteHtml.endpoints[0].label, `${CARRIER_TELECOM}-01`);
assert.equal(remoteHtml.endpoints[1].label, `${CARRIER_MOBILE}-01`);

const remoteHtmlNoCarrier = extractPreferredEndpointsFromContent(
  `
  <table>
    <tr><td>104.16.40.1</td><td>18 ms</td></tr>
    <tr><td>104.17.50.2</td><td>22 ms</td></tr>
  </table>
  `,
  {
    defaultPort: 443,
    carrierFilters: `${CARRIER_TELECOM},${CARRIER_MOBILE}`,
    maxEndpoints: 2,
  },
);
assert.equal(remoteHtmlNoCarrier.parser, 'html');
assert.equal(remoteHtmlNoCarrier.endpoints.length, 2);
assert.equal(remoteHtmlNoCarrier.endpoints[0].host, '104.16.40.1');
assert.equal(remoteHtmlNoCarrier.endpoints[1].host, '104.17.50.2');

const latestTimestamp = extractLatestTimestampFromContent(
  `
  更新时间：2026-03-22 10:30:15
  数据生成于 2026/03/22 09:20:00
  `,
);
assert.equal(latestTimestamp, '2026-03-22T02:30:15.000Z');

const raw = renderRawSubscription(expanded.nodes);
assert.ok(raw.length > 10);

const clash = renderClashSubscription(expanded.nodes);
assert.match(clash, /proxies:/);
assert.match(clash, /edge\.example\.com/);

const surge = renderSurgeSubscription(expanded.nodes, 'https://sub.example.com/sub/demo?target=surge');
assert.match(surge, /\[Proxy]/);
assert.match(surge, /vmess/);

const secret = 'this-is-a-very-secret-key';
const token = await encryptPayload({ nodes: expanded.nodes }, secret);
const payload = await decryptPayload(token, secret);
assert.equal(payload.nodes.length, 2);

class MemoryKvNamespace {
  constructor(initialEntries = {}) {
    this.store = new Map(Object.entries(initialEntries));
  }

  async get(key) {
    return this.store.has(key) ? this.store.get(key) : null;
  }

  async put(key, value) {
    this.store.set(key, value);
  }

  async list(options = {}) {
    const prefix = options.prefix || '';
    const limit = options.limit || 1000;
    const cursor = Number.parseInt(String(options.cursor || '0'), 10) || 0;
    const keys = [...this.store.keys()]
      .filter((key) => key.startsWith(prefix))
      .sort();
    const page = keys.slice(cursor, cursor + limit);
    const nextCursor = cursor + page.length;

    return {
      keys: page.map((name) => ({ name })),
      list_complete: nextCursor >= keys.length,
      cursor: nextCursor >= keys.length ? undefined : String(nextCursor),
    };
  }
}

const nowIso = new Date().toISOString();
const staleIso = new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString();
const kv = new MemoryKvNamespace({
  'sub:remote-demo': JSON.stringify({
    version: 2,
    createdAt: staleIso,
    updatedAt: staleIso,
    baseNodes: nodes,
    options: { keepOriginalHost: true, namePrefix: 'CF' },
    sourceConfig: {
      manualPreferredIps: '',
      remoteSourceUrl: 'https://remote.example.com/ip-list.json',
      refreshHours: 1,
      remoteDefaultPort: 443,
      remoteCarrierFilters: [CARRIER_TELECOM, CARRIER_MOBILE],
      remoteMaxAgeHours: 6,
      maxEndpoints: 2,
    },
    cache: {
      endpoints: [{ host: '104.16.1.2', port: 443, label: 'old' }],
      fetchedAt: staleIso,
      parser: 'json',
      sourceUpdatedAt: staleIso,
    },
  }),
  'sub:manual-demo': JSON.stringify({
    version: 2,
    createdAt: nowIso,
    updatedAt: nowIso,
    baseNodes: nodes,
    options: { keepOriginalHost: true, namePrefix: 'CF' },
    sourceConfig: {
      manualPreferredIps: '104.16.8.8#Manual',
      remoteSourceUrl: '',
      refreshHours: 3,
      remoteDefaultPort: 443,
      remoteCarrierFilters: [],
      remoteMaxAgeHours: 6,
      maxEndpoints: 1,
    },
    cache: null,
  }),
});

const env = { SUB_STORE: kv };
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
  assert.match(String(url), /remote\.example\.com/);
  return new Response(
    JSON.stringify({
      updated_at: nowIso,
      data: [
        { ip: '104.16.99.1', carrier: CARRIER_TELECOM },
        { ip: '104.18.99.2', carrier: CARRIER_MOBILE },
      ],
    }),
    {
      status: 200,
      headers: {
        'content-type': 'application/json; charset=utf-8',
      },
    },
  );
};

try {
  const summary = await runScheduledRefresh(env);
  assert.equal(summary.scanned, 2);
  assert.equal(summary.remote, 1);
  assert.equal(summary.updated, 1);
  assert.equal(summary.skippedManual, 1);
  assert.equal(summary.failed, 0);

  const refreshedRecord = JSON.parse(await kv.get('sub:remote-demo'));
  assert.equal(refreshedRecord.cache.endpoints.length, 2);
  assert.equal(refreshedRecord.cache.endpoints[0].host, '104.16.99.1');
  assert.equal(refreshedRecord.refreshState.status, 'success');
  assert.equal(refreshedRecord.refreshState.reason, 'scheduled');
} finally {
  globalThis.fetch = originalFetch;
}

console.log('smoke test passed');
