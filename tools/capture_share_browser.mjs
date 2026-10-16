#!/usr/bin/env node
// Node.js 22+; observes an existing page through CDP. No navigation or UI input.
import { open } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const help = `Capture one actual TeraBox browser /api/srn/ck request.
Requires Node.js 22+ built-in fetch and WebSocket; no packages required.

Usage:
  node tools/capture_share_browser.mjs --endpoint http://127.0.0.1:9222 --target-id TARGET --output PRIVATE.json [--timeout 60]

--endpoint   Existing HTTP(S) CDP discovery origin, or exact page WS(S) URL.
--target-id  Explicit existing page target ID; never chosen automatically.
--output     New private observation JSON file; existing files are refused.
--timeout    Observation deadline in seconds, greater than 0 and at most 120.
--help       Print this help without connecting.

The tool subscribes to Network events and waits for your actual click.
It does not launch Chrome, navigate, click, generate tokens, or send the click.
Request URL, headers and body are private and are written only to --output.
`;

export function parseArguments(args) {
  if (args.length === 1 && args[0] === '--help') return { help: true };
  const values = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i];
    if (!['--endpoint', '--target-id', '--output', '--timeout'].includes(key) || values[key] !== undefined || !args[i + 1]) throw new Error('invalid_arguments');
    values[key] = args[i + 1];
  }
  const timeout = Number(values['--timeout'] ?? 60);
  if (!values['--endpoint'] || !values['--target-id'] || !values['--output'] || !Number.isFinite(timeout) || timeout <= 0 || timeout > 120 || /[\s\x00-\x1f]/u.test(values['--target-id'])) throw new Error('invalid_arguments');
  const endpoint = new URL(values['--endpoint']);
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.hash || endpoint.search) throw new Error('invalid_endpoint');
  if (['http:', 'https:'].includes(endpoint.protocol) && endpoint.pathname !== '/') throw new Error('invalid_endpoint');
  return { endpoint, targetID: values['--target-id'], output: values['--output'], timeoutMS: timeout * 1000 };
}

function shareRequest(request) {
  try {
    const url = new URL(request.url);
    return request.method === 'POST' && url.protocol === 'https:' && !url.username && !url.password && !url.port &&
      (url.hostname === 'terabox.com' || url.hostname.endsWith('.terabox.com')) && url.pathname === '/api/srn/ck';
  } catch { return false; }
}

export function mergeObservedHeaders(base, extra) {
  const result = new Map();
  for (const source of [base, extra]) {
    const seen = new Set();
    for (const [name, rawValue] of Object.entries(source ?? {})) {
      const key = name.toLowerCase();
      if (!key || seen.has(key) || typeof rawValue !== 'string' || /[\r\n\x00]/u.test(name + rawValue)) throw new Error('invalid_observed_headers');
      seen.add(key);
      result.set(key, rawValue);
    }
  }
  return Object.fromEntries(result);
}

async function discoverSocket(options, signal) {
  if (['ws:', 'wss:'].includes(options.endpoint.protocol)) {
    if (options.endpoint.pathname !== `/devtools/page/${encodeURIComponent(options.targetID)}`) throw new Error('target_mismatch');
    return options.endpoint.href;
  }
  const response = await fetch(new URL('/json/list', options.endpoint), { signal, redirect: 'error' });
  if (!response.ok) throw new Error('discovery_failed');
  const text = await response.text();
  if (text.length > 4 * 1024 * 1024) throw new Error('discovery_too_large');
  const targets = JSON.parse(text);
  if (!Array.isArray(targets)) throw new Error('discovery_failed');
  const matching = targets.filter(target => target.id === options.targetID);
  if (matching.length !== 1 || !['page', 'webview'].includes(matching[0].type)) throw new Error('target_not_found');
  const socket = new URL(matching[0].webSocketDebuggerUrl);
  if (!['ws:', 'wss:'].includes(socket.protocol) || socket.username || socket.password || socket.search || socket.hash ||
      socket.hostname !== options.endpoint.hostname || socket.pathname !== `/devtools/page/${encodeURIComponent(options.targetID)}`) throw new Error('unsafe_target_socket');
  return socket.href;
}

export async function capture(options) {
  if (Number(process.versions.node.split('.')[0]) < 22 || typeof fetch !== 'function' || typeof WebSocket !== 'function') throw new Error('node_22_required');
  const signal = AbortSignal.timeout(options.timeoutMS);
  const address = await discoverSocket(options, signal);
  const socket = new WebSocket(address);
  const pending = new Map();
  const requests = new Map();
  let nextID = 0;
  let settled = false;
  let observationResolve, observationReject;
  const observed = new Promise((resolve, reject) => { observationResolve = resolve; observationReject = reject; });
  const fail = () => { if (!settled) { settled = true; observationReject(new Error('observation_failed')); } };
  const command = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextID;
    pending.set(id, { resolve, reject });
    try { socket.send(JSON.stringify({ id, method, params })); } catch { pending.delete(id); reject(new Error('cdp_command_failed')); }
  });
  const complete = async state => {
    if (settled || state.processing || !state.request || !state.extra || !shareRequest(state.request)) return;
    state.processing = true;
    try {
      if (state.ambiguous) throw new Error('ambiguous_request');
      let body = state.request.postData;
      if (typeof body !== 'string') {
        const result = await command('Network.getRequestPostData', { requestId: state.requestID });
        body = result.postData;
      }
      if (typeof body !== 'string' || body.length === 0 || Buffer.byteLength(body) > 1024 * 1024 || state.request.url.length > 1024 * 1024) throw new Error('missing_request_body');
      const headers = mergeObservedHeaders(state.request.headers, state.extra.headers);
      if (!headers['user-agent'] || !headers.referer || !headers['content-type']) throw new Error('missing_request_headers');
      const timestamp = Number.isFinite(state.wallTime) && state.wallTime > 0 ? new Date(state.wallTime * 1000) : state.receivedAt;
      const result = { method: state.request.method, url: state.request.url, headers, body, observed_at: timestamp.toISOString() };
      if (!settled) { settled = true; observationResolve(result); }
    } catch { fail(); }
  };
  socket.addEventListener('message', event => {
    try {
      const message = JSON.parse(event.data);
      if (message.id) {
        const entry = pending.get(message.id);
        if (!entry) return;
        pending.delete(message.id);
        if (message.error) entry.reject(new Error('cdp_command_failed')); else entry.resolve(message.result ?? {});
        return;
      }
      if (!['Network.requestWillBeSent', 'Network.requestWillBeSentExtraInfo'].includes(message.method)) return;
      const data = message.params;
      if (!data?.requestId) return;
      let state = requests.get(data.requestId);
      if (!state) {
        if (requests.size >= 10000) throw new Error('request_limit');
        state = { requestID: data.requestId };
        requests.set(data.requestId, state);
      }
      if (message.method === 'Network.requestWillBeSent') {
        if (state.request || data.redirectResponse) state.ambiguous = true;
        state.request = data.request;
        state.wallTime = data.wallTime;
        state.receivedAt = new Date();
      } else {
        if (state.extra) state.ambiguous = true;
        state.extra = data;
      }
      void complete(state);
    } catch { fail(); }
  });
  socket.addEventListener('error', fail);
  socket.addEventListener('close', fail);
  signal.addEventListener('abort', fail, { once: true });
  try {
    if (signal.aborted) throw new Error('observation_timeout');
    await Promise.race([new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', () => reject(new Error('cdp_connection_failed')), { once: true });
    }), observed]);
    await Promise.race([command('Network.enable', { maxPostDataSize: 1024 * 1024 }), observed]);
    process.stderr.write('Observing the selected existing target; perform the share-page click in that browser.\n');
    return await observed;
  } finally {
    settled = true;
    signal.removeEventListener('abort', fail);
    for (const entry of pending.values()) entry.reject(new Error('cdp_closed'));
    pending.clear();
    socket.close();
  }
}

async function main() {
  let file;
  try {
    const options = parseArguments(process.argv.slice(2));
    if (options.help) { process.stdout.write(help); return; }
    // Reserve the exact output before connecting; never overwrite a capture.
    file = await open(options.output, 'wx', 0o600);
    const observation = await capture(options);
    await file.writeFile(JSON.stringify(observation, null, 2) + '\n', 'utf8');
    await file.sync();
    process.stderr.write('One observed request saved. No server result or acquisition credit was inferred.\n');
  } catch {
    process.stderr.write('Capture failed; no request values were printed. Check arguments, target availability, output-file existence and timeout.\n');
    process.exitCode = 1;
  } finally {
    await file?.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
