import assert from 'node:assert/strict';
import {
  decryptPayload,
  encryptPayload,
  expandNodes,
  extractPreferredEndpointsFromContent,
  parseNodeLinks,
  parsePreferredEndpoints,
  renderClashSubscription,
  renderRawSubscription,
  renderSurgeSubscription,
} from '../src/core.js';

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

console.log('smoke test passed');
