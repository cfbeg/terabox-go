import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, rmdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { capture, mergeObservedHeaders, parseArguments } from './capture_share_browser.mjs';

const url = 'https://www.terabox.com/api/srn/ck?jsToken=private-observed-token';
const body = 'pid=tera_sharelink&tera_link_id=private-observed-link';
const headers = { 'User-Agent': 'observed-agent', Referer: 'https://www.terabox.com/wap/share/filelist', 'Content-Type': 'application/x-www-form-urlencoded' };

async function fakeCapture(events, options = {}) {
  const original = globalThis.WebSocket;
  const commands = [];
  class FakeSocket extends EventTarget {
    constructor() {
      super();
      this.keepAlive = setInterval(() => {}, 10);
      queueMicrotask(() => this.dispatchEvent(new Event('open')));
    }
    message(value) { this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(value) })); }
    send(encoded) {
      const request = JSON.parse(encoded);
      commands.push(request.method);
      queueMicrotask(() => {
        this.message({ id: request.id, result: request.method === 'Network.getRequestPostData' ? { postData: body } : {} });
        if (request.method === 'Network.enable') for (const event of events) this.message(event);
      });
    }
    close() { clearInterval(this.keepAlive); }
  }
  globalThis.WebSocket = FakeSocket;
  try {
    return { result: await capture({ endpoint: new URL('ws://127.0.0.1:9222/devtools/page/fixture'), targetID: 'fixture', timeoutMS: 1000, ...options }), commands };
  } finally { globalThis.WebSocket = original; }
}

function requestEvent(hasBody = true) {
  return { method: 'Network.requestWillBeSent', params: { requestId: 'fixture-request', wallTime: 1792152000,
    request: { method: 'POST', url, headers, ...(hasBody ? { postData: body } : { hasPostData: true }) } } };
}
const extraEvent = { method: 'Network.requestWillBeSentExtraInfo', params: { requestId: 'fixture-request', headers: { ...headers, Cookie: 'private-observed-cookie' } } };

test('captures either CDP event ordering with actual extra headers and body', async () => {
  for (const events of [[requestEvent(), extraEvent], [extraEvent, requestEvent()]]) {
    const { result, commands } = await fakeCapture(events);
    assert.equal(result.url, url);
    assert.equal(result.body, body);
    assert.equal(result.headers.cookie, 'private-observed-cookie');
    assert.equal(result.headers['user-agent'], 'observed-agent');
    assert.match(result.observed_at, /^2026-/);
    assert.deepEqual(commands, ['Network.enable']);
  }
});

test('reads omitted body from the already observed request without navigation or clicking', async () => {
  const { result, commands } = await fakeCapture([requestEvent(false), extraEvent]);
  assert.equal(result.body, body);
  assert.deepEqual(commands, ['Network.enable', 'Network.getRequestPostData']);
});

test('refuses incomplete headers, ambiguous redirect pairing and expired observation', async () => {
  const missing = { ...extraEvent, params: { requestId: 'fixture-request', headers: { Cookie: 'private' } } };
  const noHeaderRequest = requestEvent();
  noHeaderRequest.params.request.headers = {};
  await assert.rejects(fakeCapture([noHeaderRequest, missing]), /observation_failed/);
  const redirected = requestEvent();
  redirected.params.redirectResponse = {};
  await assert.rejects(fakeCapture([redirected, extraEvent]), /observation_failed/);
  await assert.rejects(fakeCapture([], { timeoutMS: 20 }), /observation_failed/);
});

test('arguments require an explicit target and bounded deadline', () => {
  assert.deepEqual(parseArguments(['--help']), { help: true });
  const base = ['--endpoint', 'http://127.0.0.1:9222', '--target-id', 'fixture', '--output', 'private.json'];
  assert.equal(parseArguments(base).timeoutMS, 60000);
  assert.equal(parseArguments([...base, '--timeout', '120']).timeoutMS, 120000);
  for (const value of ['0', '-1', '121', 'NaN', 'Infinity']) assert.throws(() => parseArguments([...base, '--timeout', value]));
  assert.throws(() => parseArguments(base.slice(0, 2)));
  assert.throws(() => parseArguments([...base, '--target-id', 'other']));
  assert.throws(() => parseArguments(['--endpoint', 'http://private:secret@localhost:9222', '--target-id', 'fixture', '--output', 'private.json']));
  assert.throws(() => mergeObservedHeaders({ Cookie: 'private', cookie: 'different' }, {}));
  assert.throws(() => mergeObservedHeaders({}, { Cookie: 'private\r\ninjection' }));
});

test('exclusive output refuses overwrite before any CDP attachment and prints no private path', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'terabox-browser-fixture-'));
  const output = join(directory, 'private-existing-observation.json');
  try {
    await writeFile(output, 'preserve-private-fixture', { mode: 0o600 });
    const run = spawnSync(process.execPath, [fileURLToPath(new URL('./capture_share_browser.mjs', import.meta.url)),
      '--endpoint', 'http://127.0.0.1:1', '--target-id', 'fixture-private-target', '--output', output], { encoding: 'utf8' });
    assert.equal(run.status, 1);
    assert.equal(await readFile(output, 'utf8'), 'preserve-private-fixture');
    assert.equal(run.stdout, '');
    assert.ok(!run.stderr.includes(directory));
    assert.ok(!run.stderr.includes('fixture-private-target'));
  } finally { await rm(output, { force: true }); await rmdir(directory); }
});
