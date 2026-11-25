// Exercise a synthetic loopback server directly or through the local Burp Proxy.
const http = require('node:http');
const http2 = require('node:http2');
const tls = require('node:tls');
const { createHash } = require('node:crypto');

const via = process.argv[2];
const paths = process.argv.slice(3);
const host = '127.0.0.1';
const port = Number(process.env.REWRITE_FIXTURE_PORT || 18080);
const authority = `${host}:${port}`;

function proxyTunnel() {
  return new Promise((resolve, reject) => {
    const request = http.request({ hostname: host, port: 8080, method: 'CONNECT', path: authority, agent: false });
    request.setTimeout(5000, () => request.destroy(new Error('CONNECT timed out')));
    request.once('error', reject);
    request.once('connect', (response, socket, remainder) => {
      if (response.statusCode !== 200) {
        socket.destroy();
        reject(new Error(`CONNECT returned ${response.statusCode}`));
        return;
      }
      if (remainder.length) socket.unshift(remainder);
      resolve(socket);
    });
    request.end();
  });
}

async function main() {
  if (!['direct', 'proxy'].includes(via) || ![18080, 18081].includes(port) ||
      !paths.length || paths.length > 12 || paths.some(path => !path.startsWith('/h2-'))) {
    throw new Error('Usage: node tools/http2_probe.js direct|proxy /h2-path [...]');
  }
  const tunnel = via === 'proxy' ? await proxyTunnel() : undefined;
  // Trust only the ephemeral certificate handshake for this fixed loopback test.
  const socket = tls.connect({ socket: tunnel, host, port, ALPNProtocols: ['h2'], rejectUnauthorized: false });
  try {
    await new Promise((resolve, reject) => {
      socket.setTimeout(5000, () => socket.destroy(new Error('TLS timed out')));
      socket.once('secureConnect', resolve);
      socket.once('error', reject);
    });
    if (socket.alpnProtocol !== 'h2') throw new Error(`ALPN did not negotiate h2: ${socket.alpnProtocol}`);
    const session = http2.connect(`https://${authority}`, { createConnection: () => socket });
    const results = await Promise.all(paths.map(path => new Promise((resolve, reject) => {
      const request = session.request({ ':path': path });
      const start = performance.now();
      let headers, trailers, firstByteMs;
      const chunks = [];
      request.setTimeout(5000, () => request.destroy(new Error(`Stream timed out: ${path}`)));
      request.once('error', reject);
      request.once('response', value => { headers = value; });
      request.once('trailers', value => { trailers = value; });
      request.on('data', chunk => {
        firstByteMs ??= Math.round(performance.now() - start);
        chunks.push(chunk);
      });
      request.once('end', () => {
        const body = Buffer.concat(chunks);
        resolve({ path, streamId: request.id, headers, trailers, firstByteMs, totalMs: Math.round(performance.now() - start),
          bytes: body.length, sha256: createHash('sha256').update(body).digest('hex'),
          body: headers?.['content-encoding'] === 'gzip' ? undefined : body.toString('utf8') });
      });
      request.end();
    })));
    console.log(JSON.stringify({ via, authority, clientAlpn: socket.alpnProtocol, results }));
    session.close();
  } finally {
    socket.destroy();
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
