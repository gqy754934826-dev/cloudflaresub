import {
  detectTarget,
  expandNodes,
  extractPreferredEndpointsFromContent,
  parseNodeLinks,
  parsePreferredEndpoints,
  renderSubscription,
  summarizeNodes,
} from './core.js';

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8', extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
      ...extraHeaders,
    },
  });
}

function normalizeLines(value = '') {
  return String(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .sort()
    .join('\n');
}

function clampInteger(value, min, max, fallback) {
  const number = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(number)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, number));
}

function normalizeCarrierFilters(value = '') {
  return String(value)
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeHttpUrl(value = '') {
  const raw = String(value || '').trim();
  if (!raw) {
    return '';
  }

  const url = new URL(raw);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('远程优选源只支持 http / https 链接。');
  }
  return url.toString();
}

function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let index = 0; index < length; index += 1) {
    out += chars[bytes[index] % chars.length];
  }
  return out;
}

async function createUniqueShortId(env, tries = 8) {
  for (let attempt = 0; attempt < tries; attempt += 1) {
    const id = createShortId(10);
    const exists = await env.SUB_STORE.get(`sub:${id}`);
    if (!exists) {
      return id;
    }
  }
  throw new Error('无法生成唯一订阅标识，请稍后再试。');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function buildDedupHash(body) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    remoteSourceUrl: String(body.remoteSourceUrl || '').trim(),
    refreshHours: clampInteger(body.refreshHours, 1, 24, 3),
    remoteDefaultPort: clampInteger(body.remoteDefaultPort, 1, 65535, 443),
    remoteCarrierFilters: normalizeCarrierFilters(body.remoteCarrierFilters || '').sort(),
    maxEndpoints: clampInteger(body.maxEndpoints, 1, 200, 12),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}

function buildSubscriptionUrls(origin, id, accessToken = '') {
  const build = (target) => {
    const params = new URLSearchParams();
    if (target) {
      params.set('target', target);
    }
    if (accessToken) {
      params.set('token', accessToken);
    }
    const query = params.toString();
    return `${origin}/sub/${id}${query ? `?${query}` : ''}`;
  };

  return {
    auto: build('auto'),
    raw: build('raw'),
    clash: build('clash'),
    surge: build('surge'),
    json: build('json'),
  };
}

function validateAccessToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN;
  if (!expected) {
    return { ok: true };
  }

  const provided = url.searchParams.get('token') || '';
  if (provided !== expected) {
    return { ok: false, response: text('Forbidden: invalid token', 403) };
  }

  return { ok: true };
}

function buildSourceConfig(body) {
  return {
    manualPreferredIps: normalizeLines(body.preferredIps || ''),
    remoteSourceUrl: normalizeHttpUrl(body.remoteSourceUrl || ''),
    refreshHours: clampInteger(body.refreshHours, 1, 24, 3),
    remoteDefaultPort: clampInteger(body.remoteDefaultPort, 1, 65535, 443),
    remoteCarrierFilters: normalizeCarrierFilters(body.remoteCarrierFilters || ''),
    maxEndpoints: clampInteger(body.maxEndpoints, 1, 200, 12),
  };
}

async function fetchRemoteEndpoints(sourceConfig) {
  const response = await fetch(sourceConfig.remoteSourceUrl, {
    headers: {
      'user-agent': 'cloudflare-sub-worker/2.0',
      accept: 'text/html,text/plain;q=0.9,*/*;q=0.8',
    },
    cf: {
      cacheEverything: false,
      cacheTtl: 0,
    },
  });

  if (!response.ok) {
    throw new Error(`远程源返回 ${response.status}`);
  }

  const content = await response.text();
  const { endpoints, warnings } = extractPreferredEndpointsFromContent(content, {
    defaultPort: sourceConfig.remoteDefaultPort,
    carrierFilters: sourceConfig.remoteCarrierFilters,
    maxEndpoints: sourceConfig.maxEndpoints,
  });

  if (!endpoints.length) {
    throw new Error(warnings[0] || '远程页面中没有解析到可用优选 IP。');
  }

  return {
    endpoints,
    warnings,
    fetchedAt: new Date().toISOString(),
  };
}

function isCacheFresh(cache, refreshHours) {
  if (!cache?.fetchedAt) {
    return false;
  }

  const fetchedAt = Date.parse(cache.fetchedAt);
  if (!Number.isFinite(fetchedAt)) {
    return false;
  }

  return Date.now() - fetchedAt < refreshHours * 60 * 60 * 1000;
}

async function resolveEndpoints(sourceConfig, cache, saveCache) {
  const warnings = [];

  if (!sourceConfig.remoteSourceUrl) {
    const manualResult = parsePreferredEndpoints(sourceConfig.manualPreferredIps || '');
    return {
      endpoints: manualResult.endpoints,
      warnings: [...manualResult.warnings],
      metadata: {
        mode: 'manual',
        fetchedAt: null,
      },
    };
  }

  if (isCacheFresh(cache, sourceConfig.refreshHours) && cache?.endpoints?.length) {
    return {
      endpoints: cache.endpoints,
      warnings,
      metadata: {
        mode: 'remote-cache',
        fetchedAt: cache.fetchedAt,
      },
    };
  }

  try {
    const remoteResult = await fetchRemoteEndpoints(sourceConfig);
    if (typeof saveCache === 'function') {
      await saveCache({
        endpoints: remoteResult.endpoints,
        fetchedAt: remoteResult.fetchedAt,
      });
    }

    return {
      endpoints: remoteResult.endpoints,
      warnings: [...remoteResult.warnings],
      metadata: {
        mode: 'remote-live',
        fetchedAt: remoteResult.fetchedAt,
      },
    };
  } catch (error) {
    if (cache?.endpoints?.length) {
      warnings.push(`远程优选源刷新失败，已回退到 ${cache.fetchedAt} 的缓存：${error.message}`);
      return {
        endpoints: cache.endpoints,
        warnings,
        metadata: {
          mode: 'remote-stale-cache',
          fetchedAt: cache.fetchedAt,
        },
      };
    }

    if (sourceConfig.manualPreferredIps) {
      const manualResult = parsePreferredEndpoints(sourceConfig.manualPreferredIps);
      warnings.push(`远程优选源拉取失败，已回退到手动备用 IP：${error.message}`);
      warnings.push(...manualResult.warnings);
      return {
        endpoints: manualResult.endpoints,
        warnings,
        metadata: {
          mode: 'manual-fallback',
          fetchedAt: null,
        },
      };
    }

    throw error;
  }
}

async function buildNodesFromRecord(record, env, id) {
  if (Array.isArray(record.nodes) && !record.baseNodes) {
    return {
      nodes: record.nodes,
      warnings: [],
      metadata: {
        mode: 'legacy-static',
        fetchedAt: record.createdAt || null,
      },
    };
  }

  const baseNodes = Array.isArray(record.baseNodes) ? record.baseNodes : [];
  if (!baseNodes.length) {
    throw new Error('订阅记录中没有可用节点。');
  }

  const resolved = await resolveEndpoints(record.sourceConfig || {}, record.cache, async (nextCache) => {
    const updatedRecord = {
      ...record,
      cache: nextCache,
      updatedAt: new Date().toISOString(),
    };
    await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(updatedRecord));
  });

  const expanded = expandNodes(baseNodes, resolved.endpoints, record.options || {});
  return {
    nodes: expanded.nodes,
    warnings: [...resolved.warnings, ...expanded.warnings],
    metadata: resolved.metadata,
  };
}

async function handleGenerate(request, env, url) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是有效的 JSON。' }, 400);
  }

  let baseNodeResult;
  try {
    baseNodeResult = parseNodeLinks(body.nodeLinks || '');
  } catch (error) {
    return json({ ok: false, error: error.message }, 400);
  }

  let sourceConfig;
  try {
    sourceConfig = buildSourceConfig(body);
  } catch (error) {
    return json({ ok: false, error: error.message }, 400);
  }

  if (!sourceConfig.manualPreferredIps && !sourceConfig.remoteSourceUrl) {
    return json({ ok: false, error: '请至少填写手动优选 IP，或者提供远程优选源 URL。' }, 400);
  }

  const options = {
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };

  let resolved;
  try {
    resolved = await resolveEndpoints(sourceConfig, null);
  } catch (error) {
    return json({ ok: false, error: `生成预览失败：${error.message}` }, 502);
  }

  const expanded = expandNodes(baseNodeResult.nodes, resolved.endpoints, options);

  const payload = {
    version: 2,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    baseNodes: baseNodeResult.nodes,
    options,
    sourceConfig,
    cache:
      resolved.metadata.fetchedAt && resolved.endpoints.length
        ? {
            endpoints: resolved.endpoints,
            fetchedAt: resolved.metadata.fetchedAt,
          }
        : null,
  };

  const dedupHash = await buildDedupHash(body);
  const dedupKey = `dedup:${dedupHash}`;

  let id = await env.SUB_STORE.get(dedupKey);
  if (!id) {
    id = await createUniqueShortId(env);
    await env.SUB_STORE.put(dedupKey, id);
  }

  await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload));

  const accessToken = env.SUB_ACCESS_TOKEN || '';
  const urls = buildSubscriptionUrls(url.origin, id, accessToken);

  return json({
    ok: true,
    storage: 'kv',
    shortId: id,
    urls,
    counts: {
      inputNodes: baseNodeResult.nodes.length,
      preferredEndpoints: resolved.endpoints.length,
      outputNodes: expanded.nodes.length,
    },
    source: {
      mode: sourceConfig.remoteSourceUrl ? 'remote' : 'manual',
      remoteSourceUrl: sourceConfig.remoteSourceUrl || null,
      refreshHours: sourceConfig.remoteSourceUrl ? sourceConfig.refreshHours : null,
      carrierFilters: sourceConfig.remoteCarrierFilters,
      maxEndpoints: sourceConfig.maxEndpoints,
      lastFetchedAt: resolved.metadata.fetchedAt,
    },
    preview: summarizeNodes(expanded.nodes, 20),
    warnings: [...baseNodeResult.warnings, ...resolved.warnings, ...expanded.warnings],
  });
}

async function handleSub(request, url, env) {
  const tokenCheck = validateAccessToken(url, env);
  if (!tokenCheck.ok) {
    return tokenCheck.response;
  }

  const id = url.pathname.split('/').pop();
  if (!id) {
    return text('missing id', 400);
  }

  const raw = await env.SUB_STORE.get(`sub:${id}`);
  if (!raw) {
    return text('not found', 404);
  }

  const record = JSON.parse(raw);

  let built;
  try {
    built = await buildNodesFromRecord(record, env, id);
  } catch (error) {
    return text(`subscription build failed: ${error.message}`, 502);
  }

  const target = detectTarget(
    request.headers.get('user-agent') || '',
    url.searchParams.get('target') || 'auto',
  );

  let rendered;
  try {
    const requestUrl = new URL(url.toString());
    requestUrl.searchParams.set('target', target);
    rendered = renderSubscription(target, built.nodes, requestUrl.toString());
  } catch (error) {
    return text(`render failed: ${error.message}`, 500);
  }

  const headers = {};
  if (built.metadata.fetchedAt) {
    headers['x-sub-last-fetched-at'] = built.metadata.fetchedAt;
  }
  if (built.warnings.length) {
    headers['x-sub-warning-count'] = String(built.warnings.length);
  }

  return text(rendered.body, 200, rendered.contentType, headers);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type',
        },
      });
    }

    if (request.method === 'POST' && url.pathname === '/api/generate') {
      return handleGenerate(request, env, url);
    }

    if (request.method === 'GET' && url.pathname.startsWith('/sub/')) {
      return handleSub(request, url, env);
    }

    return env.ASSETS.fetch(request);
  },
};
