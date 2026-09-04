const http = require('http');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, 'dist');
const types = {
  '.html': 'text/html',
};

const zones = [
  { id: 1, name: 'daygle.net', zone_type: 'primary', dnssec: false, serial: 2 },
];

http
  .createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname.startsWith('/api/')) {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }
    let fp = path.join(root, u.pathname === '/' ? 'index.html' : u.pathname);
    if (!fs.existsSync(fp)) {
      res.statusCode = 404;
      res.end('not found');
      return;
    }
    res.setHeader('Content-Type', types[path.extname(fp)] || 'application/octet-stream');
    fs.createReadStream(fp).pipe(res);
  })
  .listen(5173, '127.0.0.1', () => console.log('stub server on http://127.0.0.1:5173'));
