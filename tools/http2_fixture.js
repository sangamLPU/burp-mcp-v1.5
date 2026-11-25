// Loopback-only HTTP/2 fixture. Set REWRITE_FIXTURE_P12 to negotiate h2 over TLS.
const http2 = require('node:http2');
const fs = require('node:fs');
const { gzipSync } = require('node:zlib');
const { createHash } = require('node:crypto');

const server = process.env.REWRITE_FIXTURE_P12
  ? http2.createSecureServer({ pfx: fs.readFileSync(process.env.REWRITE_FIXTURE_P12), passphrase: 'fixture-only' })
  : http2.createServer();
server.on('stream', (stream, headers) => {
  const path = headers[':path'].split('?')[0];
  const record = {
    alpn: stream.session.socket.alpnProtocol || 'h2c',
    streamId: stream.id,
    method: headers[':method'],
    path: headers[':path'],
  };
  const body = JSON.stringify({
    ...record,
    fixtureFlag: false,
    user: { score: 10, preserve: 'café' },
    items: [{ fixtureFlag: false, keep: 'original' }],
    keep: 'original',
  });

  const response = { ':status': 200, 'content-type': 'application/json' };
  let payload = Buffer.from(body);
  switch (path) {
    case '/fixture-h2':
      payload = Buffer.from(JSON.stringify({ method: record.method, path: record.path,
        isPremium: false, keep: 'original', unicode: 'café' }));
      break;
    case '/h2-empty':
      payload = Buffer.alloc(0);
      break;
    case '/h2-text':
      response['content-type'] = 'text/plain; charset=utf-8';
      payload = Buffer.from('Keep prefix. Fixture status: original. Keep café.');
      break;
    case '/h2-malformed':
      payload = Buffer.from('{"fixtureFlag":false');
      break;
    case '/h2-gzip':
      response['content-encoding'] = 'gzip';
      payload = gzipSync(Buffer.from('{"fixtureFlag":false,"keep":"original"}'));
      break;
    case '/h2-partial':
      response[':status'] = 206;
      response['content-range'] = `bytes 0-${payload.length - 1}/${payload.length + 1}`;
      break;
    case '/h2-events':
      response['content-type'] = 'text/event-stream';
      stream.respond(response);
      stream.write('data: {"fixtureFlag":false}\n\n');
      setTimeout(() => {
        if (!stream.destroyed) stream.end('data: {"keep":"original"}\n\n');
      }, 250);
      return;
  }

  if (path !== '/h2-no-length') response['content-length'] = payload.length;
  if (path === '/h2-trailers' || path === '/h2-digest') {
    const trailers = path === '/h2-digest'
      ? { 'content-digest': `sha-256=:${createHash('sha256').update(payload).digest('base64')}:` }
      : { 'x-fixture-trailer': 'retained' };
    stream.respond(response, { waitForTrailers: true });
    stream.once('wantTrailers', () => stream.sendTrailers(trailers));
  } else {
    stream.respond(response);
  }
  stream.end(payload);
});
server.listen(Number(process.env.REWRITE_FIXTURE_PORT || 18080), '127.0.0.1');
