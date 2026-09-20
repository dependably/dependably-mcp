import net from 'node:net';
import { DependablyClient } from '/Users/michael/Projects/dependably-mcp/.claude/worktrees/agent-a6b6cf3bc3bcc438a/dist/client.js';
import { fetchEcosystems } from '/Users/michael/Projects/dependably-mcp/.claude/worktrees/agent-a6b6cf3bc3bcc438a/dist/ecosystems.js';
import { buildServer } from '/Users/michael/Projects/dependably-mcp/.claude/worktrees/agent-a6b6cf3bc3bcc438a/dist/server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
// real ECONNREFUSED
const s = net.createServer(); await new Promise(r=>s.listen(0,'127.0.0.1',r));
const port = s.address().port; await new Promise(r=>s.close(r));
const r = await fetchEcosystems(new DependablyClient({baseUrl:`http://127.0.0.1:${port}`, token:'t', timeoutMs:3000}));
console.log('real refused reason =>', JSON.stringify(r.reason));
// empty setup intersection
const cfg = {baseUrl:'https://x.example', token:'t', timeoutMs:1000};
const planes = { registry:['hex','apk'], lookup:['hex'], setup:['hex','apk'] };
const srv = buildServer(new DependablyClient(cfg), cfg, planes);
const [ct,st] = InMemoryTransport.createLinkedPair();
const c = new Client({name:'x',version:'0'});
await Promise.all([srv.connect(st), c.connect(ct)]);
const {tools} = await c.listTools();
const e=(n)=>tools.find(t=>t.name===n)?.inputSchema?.properties?.ecosystem?.enum;
console.log('empty-intersection install enum =>', JSON.stringify(e('get_install_command')));
console.log('registry enum =>', JSON.stringify(e('list_packages')), 'lookup =>', JSON.stringify(e('lookup_package')));
await c.close(); await srv.close();
