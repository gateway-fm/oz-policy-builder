// Serve app.html on loopback only. WebAuthn needs a secure context, and `http://localhost` is one;
// binding to 127.0.0.1 keeps the page off every other interface.
//
//   node server.mjs            # then open http://localhost:5177 in a browser with a passkey
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const page = readFileSync(new URL('./app.html', import.meta.url));

/** Listen on `port` (0 for any free port); `OZPB_PASSKEY_PORT` or 5177 when run by hand. */
export function serve(port = Number(process.env.OZPB_PASSKEY_PORT ?? 5177)) {
  const server = http.createServer((req, res) => {
    if (req.method !== 'GET' || req.url !== '/') {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(page);
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const server = await serve();
  console.log(`serving http://localhost:${server.address().port}`);
}
