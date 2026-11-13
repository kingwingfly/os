// A Docker API socket in front of Podman's, for wrangler. workerd asks for memory swappiness 0
// in every container it creates. Docker ignores that on cgroup v2; Podman hands it to crun,
// which refuses it ("cannot set memory swappiness with cgroupv2") wherever it applies cgroups,
// as in a systemd user session, so no container starts. This drops the setting from
// container-create requests and passes everything else through as it is.
import http from 'node:http';
import net from 'node:net';
import { rmSync } from 'node:fs';

const creates = /^(\/v[\d.]+)?\/containers\/create(\?|$)/;

/// Listen at the socket `listen`, forwarding to Podman's at `upstream`.
export function podmanProxy(listen, upstream) {
  rmSync(listen, { force: true });
  const server = http.createServer((req, res) => {
    const send = body => {
      const headers = { ...req.headers };
      if (body) { delete headers['transfer-encoding']; headers['content-length'] = Buffer.byteLength(body); }
      const forwarded = http.request({ socketPath: upstream, method: req.method, path: req.url, headers }, reply => {
        res.writeHead(reply.statusCode, reply.rawHeaders);
        // A stream cut short (Podman stopped, a container killed while attached) ends the
        // reply rather than throwing an unhandled error.
        reply.on('error', () => res.destroy());
        reply.pipe(res);
      });
      forwarded.on('error', error => {
        if (res.headersSent || res.destroyed) res.destroy();
        else { res.writeHead(502); res.end(String(error)); }
      });
      // A client that goes away (a long poll such as /wait aborted) releases Podman's side too.
      res.on('close', () => { if (!res.writableFinished) forwarded.destroy(); });
      if (body) forwarded.end(body); else req.pipe(forwarded);
    };
    req.on('error', () => res.destroy());
    if (req.method !== 'POST' || !creates.test(req.url)) return send();
    const parts = [];
    req.on('data', part => parts.push(part));
    req.on('end', () => {
      let body = Buffer.concat(parts).toString();
      try {
        const create = JSON.parse(body);
        if (create.HostConfig) delete create.HostConfig.MemorySwappiness;
        body = JSON.stringify(create);
      } catch {}
      send(body);
    });
  });
  // Attaching to a container takes over the connection: pass it through whole.
  server.on('upgrade', (req, client, head) => {
    const connection = net.connect(upstream, () => {
      const lines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
      for (let i = 0; i < req.rawHeaders.length; i += 2) lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
      connection.write(lines.join('\r\n') + '\r\n\r\n');
      connection.write(head);
      client.pipe(connection).pipe(client);
    });
    connection.on('error', () => client.destroy());
    client.on('error', () => connection.destroy());
  });
  server.listen(listen);
  process.on('exit', () => rmSync(listen, { force: true }));
  return server;
}
