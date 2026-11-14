// The run's Docker API socket, in front of the engine Wrangler uses: Docker, or the run's own
// Podman service. It labels every container it creates with the run's identity, so cleanup can
// remove exactly those. For Podman it also drops the memory swappiness workerd asks for, which
// crun refuses on cgroup v2 (scripts/podman-proxy.mjs does the same for `npm run dev`; sharing
// the two is a follow-up in #67).
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import { rmSync } from 'node:fs';

const creates=/^(\/v[\d.]+)?\/containers\/create(\?|$)/;
// The engine's certificate names the engine's host. Node would otherwise take SNI and the
// certificate check from the forwarded client's Host header; an IP address gets no SNI (RFC 6066).
export const serverName=hostname=>net.isIP(hostname)?'':hostname;

// Listen at the socket `listen`, forwarding to `target`: {socketPath} or {hostname, port, protocol, ca, cert, key}.
export function engineProxy(listen,target,{label,stripMemorySwappiness=false}={}) {
  const secure=target.protocol==='https:';
  const tlsOptions=secure?{servername:serverName(target.hostname)}:{};
  rmSync(listen,{force:true});
  const server=http.createServer((req,res)=>{
    const send=body=>{
      const headers={...req.headers};
      if(body) {delete headers['transfer-encoding'];headers['content-length']=Buffer.byteLength(body);}
      const forwarded=(secure?https:http).request({...target,...tlsOptions,method:req.method,path:req.url,headers},reply=>{
        res.writeHead(reply.statusCode,reply.rawHeaders);
        // A stream cut short (the engine stopped, a container killed while attached) ends the reply.
        reply.on('error',()=>res.destroy());
        reply.pipe(res);
      });
      forwarded.on('error',error=>{
        if(res.headersSent||res.destroyed)res.destroy();
        else {res.writeHead(502);res.end(String(error));}
      });
      // A client that goes away (an aborted long poll such as /wait) releases the engine's side too.
      res.on('close',()=>{if(!res.writableFinished)forwarded.destroy();});
      if(body)forwarded.end(body);else req.pipe(forwarded);
    };
    req.on('error',()=>res.destroy());
    if(req.method!=='POST'||!creates.test(req.url))return send();
    const parts=[];
    req.on('data',part=>parts.push(part));
    req.on('end',()=>{
      let body=Buffer.concat(parts).toString();
      try {
        const create=JSON.parse(body);
        if(stripMemorySwappiness&&create.HostConfig)delete create.HostConfig.MemorySwappiness;
        if(label)create.Labels={...create.Labels,...label};
        body=JSON.stringify(create);
      } catch {}
      send(body);
    });
  });
  // Attaching to a container takes over the connection: pass it through whole.
  server.on('upgrade',(req,client,head)=>{
    const options=target.socketPath?{path:target.socketPath}:{...target,...tlsOptions,host:target.hostname};
    const connection=(secure?tls:net).connect(options,()=>{
      const lines=[`${req.method} ${req.url} HTTP/${req.httpVersion}`];
      for(let i=0;i<req.rawHeaders.length;i+=2)lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i+1]}`);
      connection.write(lines.join('\r\n')+'\r\n\r\n');
      connection.write(head);
      client.pipe(connection).pipe(client);
    });
    connection.on('error',()=>client.destroy());
    client.on('error',()=>connection.destroy());
    client.on('close',()=>connection.destroy());
  });
  // Explicit shutdown includes upgraded attach streams as well as HTTP sockets.
  const sockets=new Set();
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
  server.destroyAllSockets=()=>{for(const socket of sockets)socket.destroy();};
  server.listen(listen);
  const cleanup=()=>rmSync(listen,{force:true});
  process.once('exit',cleanup);
  server.once('close',()=>{process.off('exit',cleanup);cleanup();});
  return server;
}
