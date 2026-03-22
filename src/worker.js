import {
  detectTarget,
  expandNodes,
  extractPreferredEndpointsFromContent,
  extractLatestTimestampFromContent,
  parseNodeLinks,
  parsePreferredEndpoints,
  renderSubscription,
  summarizeNodes,
} from './core.js';

const SUBSCRIPTION_KEY_PREFIX = 'sub:';
const KV_LIST_PAGE_SIZE = 100;

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
    const exists = await env.SUB_STORE.get(buildSubscriptionKey(id));
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
    remoteMaxAgeHours: clampInteger(body.remoteMaxAgeHours, 1, 168, 6),
    maxEndpoints: clampInteger(body.maxEndpoints, 1, 200, 12),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}

function buildSubscriptionKey(id) {
  return `${SUBSCRIPTION_KEY_PREFIX}${id}`;
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
    remoteMaxAgeHours: clampInteger(body.remoteMaxAgeHours, 1, 168, 6),
    maxEndpoints: clampInteger(body.maxEndpoints, 1, 200, 12),
  };
}

async function fetchRemoteEndpoints(sourceConfig) {
  const requestUrl = new URL(sourceConfig.remoteSourceUrl);
  requestUrl.searchParams.set('_ts', String(Date.now()));

  const response = await fetch(requestUrl.toString(), {
    headers: {
      'user-agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
      accept:
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
      'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
      'cache-control': 'no-cache, no-store, max-age=0',
      pragma: 'no-cache',
      referer: requestUrl.origin + '/',
    },
    cf: {
      cacheEverything: false,
      cacheTtl: 0,
    },
  });

  if (!response.ok) {
    throw new Error(`远程源返回 ${response.status}`);
  }

  const contentType = response.headers.get('content-type') || '';
  const content = await response.text();
  const sourceUpdatedAt = extractLatestTimestampFromContent(content, { contentType });
  const { endpoints, warnings, parser } = extractPreferredEndpointsFromContent(content, {
    defaultPort: sourceConfig.remoteDefaultPort,
    carrierFilters: sourceConfig.remoteCarrierFilters,
    maxEndpoints: sourceConfig.maxEndpoints,
    contentType,
  });

  if (sourceUpdatedAt) {
    const maxAgeMs = sourceConfig.remoteMaxAgeHours * 60 * 60 * 1000;
    const sourceAgeMs = Date.now() - Date.parse(sourceUpdatedAt);
    if (Number.isFinite(sourceAgeMs) && sourceAgeMs > maxAgeMs) {
      throw new Error(
        `远程源数据时间过旧：${sourceUpdatedAt}，超过 ${sourceConfig.remoteMaxAgeHours} 小时`,
      );
    }
  } else {
    warnings.push('未识别到远程源更新时间，无法验证是否为最新数据。');
  }

  if (!endpoints.length) {
    throw new Error(warnings[0] || '远程页面中没有解析到可用优选 IP。');
  }

  return {
    endpoints,
    warnings,
    parser,
    sourceUpdatedAt,
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
        parser: 'manual',
        sourceUpdatedAt: null,
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
        parser: cache.parser || 'cache',
        sourceUpdatedAt: cache.sourceUpdatedAt || null,
      },
    };
  }

  try {
    const remoteResult = await fetchRemoteEndpoints(sourceConfig);
    if (typeof saveCache === 'function') {
      await saveCache({
        endpoints: remoteResult.endpoints,
        fetchedAt: remoteResult.fetchedAt,
        parser: remoteResult.parser || 'unknown',
        sourceUpdatedAt: remoteResult.sourceUpdatedAt || null,
      });
    }

    return {
      endpoints: remoteResult.endpoints,
      warnings: [...remoteResult.warnings],
      metadata: {
        mode: 'remote-live',
        fetchedAt: remoteResult.fetchedAt,
        parser: remoteResult.parser || 'unknown',
        sourceUpdatedAt: remoteResult.sourceUpdatedAt || null,
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
          parser: cache.parser || 'cache',
          sourceUpdatedAt: cache.sourceUpdatedAt || null,
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
          parser: 'manual-fallback',
          sourceUpdatedAt: null,
        },
      };
    }

    throw error;
  }
}

function buildCacheRecord(metadata, endpoints) {
  if (!metadata?.fetchedAt || !endpoints?.length) {
    return null;
  }

  return {
    endpoints,
    fetchedAt: metadata.fetchedAt,
    parser: metadata.parser || 'unknown',
    sourceUpdatedAt: metadata.sourceUpdatedAt || null,
  };
}

function buildRefreshState(record, status, attemptedAt, message = '', reason = 'unknown') {
  const cache = record?.cache || null;
  return {
    status,
    reason,
    message: String(message || ''),
    lastAttemptAt: attemptedAt,
    lastSuccessAt:
      status === 'success'
        ? attemptedAt
        : record?.refreshState?.lastSuccessAt || cache?.fetchedAt || null,
    fetchedAt: cache?.fetchedAt || null,
    parser: cache?.parser || null,
    sourceUpdatedAt: cache?.sourceUpdatedAt || null,
  };
}

async function persistSubscriptionRecord(env, id, record) {
  await env.SUB_STORE.put(buildSubscriptionKey(id), JSON.stringify(record));
}

async function saveRecordCache(env, id, record, nextCache, reason) {
  const attemptedAt = new Date().toISOString();
  const nextRecord = {
    ...record,
    cache: nextCache,
    updatedAt: attemptedAt,
    refreshState: buildRefreshState(
      { ...record, cache: nextCache },
      'success',
      attemptedAt,
      '',
      reason,
    ),
  };
  await persistSubscriptionRecord(env, id, nextRecord);
  return nextRecord;
}

async function saveRefreshFailure(env, id, record, message, reason) {
  const attemptedAt = new Date().toISOString();
  const nextRecord = {
    ...record,
    updatedAt: attemptedAt,
    refreshState: buildRefreshState(record, 'failed', attemptedAt, message, reason),
  };
  await persistSubscriptionRecord(env, id, nextRecord);
  return nextRecord;
}

async function buildNodesFromRecord(record, env, id) {
  if (Array.isArray(record.nodes) && !record.baseNodes) {
    return {
      nodes: record.nodes,
      warnings: [],
      metadata: {
        mode: 'legacy-static',
        fetchedAt: record.createdAt || null,
        parser: 'legacy',
        sourceUpdatedAt: null,
      },
    };
  }

  const baseNodes = Array.isArray(record.baseNodes) ? record.baseNodes : [];
  if (!baseNodes.length) {
    throw new Error('订阅记录中没有可用节点。');
  }

  const resolved = await resolveEndpoints(record.sourceConfig || {}, record.cache, async (nextCache) => {
    await saveRecordCache(env, id, record, nextCache, 'sub-request');
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
    cache: buildCacheRecord(resolved.metadata, resolved.endpoints),
  };

  const dedupHash = await buildDedupHash(body);
  const dedupKey = `dedup:${dedupHash}`;

  let id = await env.SUB_STORE.get(dedupKey);
  if (!id) {
    id = await createUniqueShortId(env);
    await env.SUB_STORE.put(dedupKey, id);
  }

  await persistSubscriptionRecord(env, id, payload);

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
      remoteMaxAgeHours: sourceConfig.remoteMaxAgeHours,
      maxEndpoints: sourceConfig.maxEndpoints,
      lastFetchedAt: resolved.metadata.fetchedAt,
      parser: resolved.metadata.parser,
      sourceUpdatedAt: resolved.metadata.sourceUpdatedAt,
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

  const raw = await env.SUB_STORE.get(buildSubscriptionKey(id));
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
  if (built.metadata.parser) {
    headers['x-sub-source-parser'] = built.metadata.parser;
  }
  if (built.metadata.sourceUpdatedAt) {
    headers['x-sub-source-updated-at'] = built.metadata.sourceUpdatedAt;
  }
  if (built.warnings.length) {
    headers['x-sub-warning-count'] = String(built.warnings.length);
  }

  return text(rendered.body, 200, rendered.contentType, headers);
}

export async function runScheduledRefresh(env) {
  const summary = {
    scanned: 0,
    remote: 0,
    updated: 0,
    skippedFresh: 0,
    skippedManual: 0,
    fallbackCache: 0,
    fallbackManual: 0,
    failed: 0,
    invalid: 0,
  };

  let cursor;
  do {
    const page = await env.SUB_STORE.list({
      prefix: SUBSCRIPTION_KEY_PREFIX,
      cursor,
      limit: KV_LIST_PAGE_SIZE,
    });

    for (const entry of page.keys) {
      const id = entry.name.slice(SUBSCRIPTION_KEY_PREFIX.length);
      summary.scanned += 1;

      try {
        const raw = await env.SUB_STORE.get(entry.name);
        if (!raw) {
          summary.invalid += 1;
          continue;
        }

        const record = JSON.parse(raw);
        const sourceConfig = record?.sourceConfig || {};
        if (!sourceConfig.remoteSourceUrl) {
          summary.skippedManual += 1;
          continue;
        }

        summary.remote += 1;
        if (isCacheFresh(record.cache, sourceConfig.refreshHours) && record?.cache?.endpoints?.length) {
          summary.skippedFresh += 1;
          continue;
        }

        let cacheSaved = false;
        const resolved = await resolveEndpoints(sourceConfig, record.cache, async (nextCache) => {
          cacheSaved = true;
          await saveRecordCache(env, id, record, nextCache, 'scheduled');
        });

        if (cacheSaved && resolved.metadata.mode === 'remote-live') {
          summary.updated += 1;
          continue;
        }

        if (resolved.metadata.mode === 'remote-stale-cache') {
          summary.fallbackCache += 1;
          await saveRefreshFailure(
            env,
            id,
            record,
            resolved.warnings[0] || 'Remote refresh failed and stale cache was used.',
            'scheduled',
          );
          continue;
        }

        if (resolved.metadata.mode === 'manual-fallback') {
          summary.fallbackManual += 1;
          await saveRefreshFailure(
            env,
            id,
            record,
            resolved.warnings[0] || 'Remote refresh failed and manual fallback was used.',
            'scheduled',
          );
          continue;
        }

        summary.failed += 1;
        await saveRefreshFailure(
          env,
          id,
          record,
          resolved.warnings[0] || `Unexpected refresh mode: ${resolved.metadata.mode}`,
          'scheduled',
        );
      } catch (error) {
        summary.failed += 1;

        try {
          const raw = await env.SUB_STORE.get(entry.name);
          if (raw) {
            const record = JSON.parse(raw);
            await saveRefreshFailure(
              env,
              id,
              record,
              error?.message || 'Unknown scheduled refresh error',
              'scheduled',
            );
          }
        } catch {}
      }
    }

    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return summary;
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
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(
      runScheduledRefresh(env).then((summary) => {
        console.log('scheduled refresh summary', JSON.stringify(summary));
      }),
    );
  },
};
