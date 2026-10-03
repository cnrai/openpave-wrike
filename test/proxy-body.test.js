// Regression tests for the proxyFetch body handling.
//
// proxyFetch() used to interpolate the request body into a single `-d <body>`
// curl argv element. execve caps one argument at MAX_ARG_STRLEN (128 KiB on
// Linux) and the whole argv+env at ARG_MAX (1 MB on macOS), so any body above
// those limits failed with E2BIG before curl ran — every POST/PUT route was
// affected (task create/update, comments, and anything else with a large
// description). Bodies above BODY_ARG_LIMIT are now streamed from a temp file
// with --data-binary @file.
//
// Harness: a local HTTP server emulates the PAVE auth proxy's _mode=json
// contract ({ok, status, headers, body}) and records every upstream request;
// the skill CLI runs as a child process with PAVE_PROXY_URL pointed at it.

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFile } = require('child_process');

const SKILL = path.join(__dirname, '..', 'index.js');
const FOLDER = 'MQAAAAECSW8i';

let server;
let proxyUrl;
let requests;
let responders;

before(async () => {
  server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      const key = Object.keys(responders).find((k) => req.url.includes(k));
      const out = key
        ? responders[key]()
        : { ok: false, status: 404, headers: {}, body: JSON.stringify({ errorDescription: 'mock/no-route/' + req.url }) };
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(out));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  proxyUrl = 'http://127.0.0.1:' + server.address().port + '/proxy';
});

after(() => server.close());

beforeEach(() => {
  requests = [];
  // The skill pre-flights the token via GET /proxy/_tokens/wrike, which reads
  // the RAW body ({has:true}) — not the _mode=json envelope.
  responders = { '/_tokens/wrike': () => ({ has: true }) };
});

// The mock proxy runs in THIS process — run the skill asynchronously so its
// synchronous curl isn't blocked by our own event loop.
function runSkill(args) {
  return new Promise((resolve, reject) => {
    execFile('node', [SKILL].concat(args), {
      encoding: 'utf8',
      env: { ...process.env, PAVE_PROXY_URL: proxyUrl },
      timeout: 30000,
    }, (err, stdout, stderr) => {
      if (err) { err.stdout = stdout; err.stderr = stderr; reject(err); return; }
      resolve(stdout);
    });
  });
}

function apiCalls() {
  return requests.filter((r) => !r.url.includes('/_tokens/'));
}

function createdTaskResponse() {
  return {
    ok: true, status: 200, headers: {},
    body: JSON.stringify({
      data: [{ id: 'IEATESTID', title: 'T', permalink: 'https://www.wrike.com/open.htm?id=IEATESTID' }],
    }),
  };
}

describe('proxyFetch streams large bodies instead of using argv', () => {
  it('creates a task with a 1.6 MB description, body intact (E2BIG before the fix)', async () => {
    responders['/folders/' + FOLDER + '/tasks'] = createdTaskResponse;

    const description = 'D'.repeat(Math.floor(1.6 * 1024 * 1024));
    const tmp = path.join(os.tmpdir(), 'wrike-test-' + process.pid + '-' + Date.now() + '.md');
    fs.writeFileSync(tmp, description);
    try {
      const out = await runSkill([
        'create', '--folder', FOLDER, '--title', 'Big description task',
        '--description-file', tmp, '--summary',
      ]);

      assert.equal(apiCalls().length, 1, 'exactly one upstream call');
      const sent = JSON.parse(apiCalls()[0].body.toString('utf8'));
      assert.equal(sent.title, 'Big description task');
      assert.equal(sent.description.length, description.length, 'description must arrive intact');
      assert.equal(sent.description, description, 'description must be byte-identical');
      assert.match(out, /Task created/, 'summary output');

      // The spilled body must be cleaned up, and must sit at least two
      // directories deep: the sandbox refuses to unlink absolute paths with
      // fewer than 3 components, so /tmp/<file>.tmp would never be removed.
      const spillDir = path.join(os.tmpdir(), 'pave-proxy-bodies');
      assert.ok(
        spillDir.split(/[\\/]/).filter(Boolean).length >= 3,
        'spill directory must be deep enough for the sandbox unlink guard: ' + spillDir,
      );
      const leftover = fs.existsSync(spillDir)
        ? fs.readdirSync(spillDir).filter((f) => f.endsWith('.tmp'))
        : [];
      assert.deepEqual(leftover, [], 'spilled body files must be cleaned up');
    } finally { fs.unlinkSync(tmp); }
  });

  it('sends a small body inline and still parses the response', async () => {
    responders['/folders/' + FOLDER + '/tasks'] = createdTaskResponse;
    await runSkill(['create', '--folder', FOLDER, '--title', 'Small task', '--description', 'brief']);
    const sent = JSON.parse(apiCalls()[0].body.toString('utf8'));
    assert.equal(sent.description, 'brief');
    assert.equal(sent.title, 'Small task');
  });
});
