/**
 * Deployment Dashboard API Server
 * Real-time control panel: PM2, GitHub, Docker, Git, PTY Terminal, Deploy Pipeline
 */

const express = require('express');
const cors = require('cors');
const { exec, spawn } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const http = require('http');
const os = require('os');

let pty;
try { pty = require('node-pty'); } catch (e) { console.warn('node-pty not available:', e.message); }

const jwt = require('jsonwebtoken');
const execAsync = util.promisify(exec);

// ============================================================================
// AUTH CONFIG
// ============================================================================

const JWT_SECRET = process.env.DASHBOARD_JWT_SECRET || 'deploy-hub-dev-secret-change-in-production';
const DASHBOARD_USER = process.env.DASHBOARD_USER || 'admin';
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'admin123';

if (!process.env.DASHBOARD_JWT_SECRET) {
  console.warn('\x1b[33m⚠ DASHBOARD_JWT_SECRET not set — using insecure default\x1b[0m');
}
if (!process.env.DASHBOARD_PASSWORD) {
  console.warn('\x1b[33m⚠ DASHBOARD_PASSWORD not set — default password is "admin123"\x1b[0m');
}

// GitHub config
const GITHUB_USERNAME = process.env.DASHBOARD_GITHUB_USER || 'adrianstanca1';

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

// Simple in-memory rate limiter for login (resets per IP per minute)
const loginAttempts = new Map();
function checkLoginRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + 60_000 };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + 60_000;
  }
  entry.count++;
  loginAttempts.set(ip, entry);
  return entry.count <= 10;
}

// ============================================================================
// PM2 HELPERS
// ============================================================================

async function getPM2List() {
  const { stdout } = await execAsync('pm2 jlist');
  const list = JSON.parse(stdout);
  return list.map(proc => ({
    name: proc.name,
    pid: proc.pid,
    status: proc.pm2_env?.status || 'unknown',
    cpu: proc.monit?.cpu || 0,
    memory: proc.monit?.memory || 0,
    restarts: proc.pm2_env?.restart_time || 0,
    uptime: proc.pm2_env?.pm_uptime ? Date.now() - proc.pm2_env.pm_uptime : 0,
    pm_id: proc.pm_id,
  }));
}

// ============================================================================
// SERVER SETUP
// ============================================================================

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  const pathname = url.pathname;

  if (pathname.startsWith('/ws')) {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request, pathname);
    });
  } else {
    socket.destroy();
  }
});

// ============================================================================
// AUTH MIDDLEWARE
// ============================================================================

function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token' });
  }
  const token = authHeader.slice(7);
  try {
    req.user = verifyToken(token);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============================================================================
// AUTH ENDPOINTS
// ============================================================================

app.post('/api/auth/login', (req, res) => {
  const ip = req.ip || req.socket.remoteAddress;
  if (!checkLoginRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many attempts. Wait 1 minute.' });
  }

  const { username, password } = req.body;
  if (username !== DASHBOARD_USER || password !== DASHBOARD_PASSWORD) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ user: username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: username });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ user: req.user.user });
});

// ============================================================================
// PM2 ENDPOINTS
// ============================================================================

app.get('/api/pm2/list', async (req, res) => {
  try {
    const list = await getPM2List();
    res.json({ success: true, data: list });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/pm2/status', async (req, res) => {
  try {
    const list = await getPM2List();
    const counts = { online: 0, stopped: 0, errored: 0, total: list.length };
    for (const proc of list) {
      if (proc.status === 'online') counts.online++;
      else if (proc.status === 'errored') counts.errored++;
      else counts.stopped++;
    }
    res.json({ success: true, data: counts });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// PM2 name validation helper
function validatePM2Name(name) {
  if (!name || !/^[a-zA-Z0-9_-]{1,100}$/.test(name)) {
    throw new Error('Invalid process name. Use alphanumeric, underscores, hyphens only (1-100 chars).');
  }
  return name;
}

app.get('/api/pm2/logs/:name', async (req, res) => {
  try {
    const { name } = req.params;
    validatePM2Name(name);
    const lines = req.query.lines || 200;
    const { stdout, stderr } = await execAsync(`pm2 logs ${name} --lines ${lines} --nostream 2>&1`);
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message, data: error.stdout || '' });
  }
});

app.post('/api/pm2/restart/:name', async (req, res) => {
  try {
    const name = validatePM2Name(req.params.name);
    await execAsync(`pm2 restart "${name}"`);
    res.json({ success: true, message: `Restarted ${name}` });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/stop/:name', async (req, res) => {
  try {
    const name = validatePM2Name(req.params.name);
    await execAsync(`pm2 stop "${name}"`);
    res.json({ success: true, message: `Stopped ${name}` });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/start/:name', async (req, res) => {
  try {
    const name = validatePM2Name(req.params.name);
    await execAsync(`pm2 start "${name}"`);
    res.json({ success: true, message: `Started ${name}` });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/delete/:name', async (req, res) => {
  try {
    const name = validatePM2Name(req.params.name);
    await execAsync(`pm2 delete "${name}"`);
    // Clean up from tracking map
    lastProcessStates.delete(name);
    res.json({ success: true, message: `Deleted ${name}` });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

// Bulk operations
app.post('/api/pm2/bulk', async (req, res) => {
  try {
    const { action, names } = req.body;
    const validActions = ['restart', 'stop', 'start', 'delete'];
    if (!validActions.includes(action)) return res.status(400).json({ success: false, error: 'Invalid action' });

    const results = await Promise.allSettled(
      names.map(name => execAsync(`pm2 ${action} "${name}"`))
    );

    const succeeded = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    res.json({ success: true, data: { succeeded, failed, total: names.length } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Restart all errored processes
app.post('/api/pm2/restart-errored', async (req, res) => {
  try {
    const processes = await getPM2List();
    const errored = processes.filter(p => p.status === 'errored').map(p => p.name);
    if (errored.length === 0) return res.json({ success: true, data: { restarted: 0 } });

    await Promise.allSettled(errored.map(name => execAsync(`pm2 restart "${name}"`)));
    res.json({ success: true, data: { restarted: errored.length, names: errored } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/save', async (req, res) => {
  try {
    await execAsync('pm2 save');
    res.json({ success: true, message: 'PM2 process list saved' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// SYSTEM COMMAND EXECUTION (WHITELISTED)
// ============================================================================

const ALLOWED_COMMANDS = [
  'pm2 save',
  'pm2 list',
  'nginx -t',
  'nginx -s reload',
  'nginx -s reopen',
  'df -h',
  'free -h',
  'uptime',
  'who',
  'last -n 10',
  'netstat -tlnp',
  'ss -tlnp',
  'systemctl status nginx',
  'systemctl reload nginx',
  'systemctl status ssh',
  'journalctl -n 50 --no-pager',
  'ps aux --sort=-%cpu | head -20',
  'ps aux --sort=-%mem | head -20',
];

app.post('/api/system/exec', async (req, res) => {
  try {
    const { command } = req.body;
    // Allow pm2 restart/stop/start/delete commands and a whitelist for system commands
    const isAllowed = ALLOWED_COMMANDS.includes(command) ||
      /^pm2 (restart|stop|start|delete|save|jlist|logs) .{0,100}$/.test(command) ||
      /^git -C \/var\/www\/.{1,100} (pull|status|log|diff) .{0,100}$/.test(command);

    if (!isAllowed) {
      return res.status(403).json({ success: false, error: 'Command not in allowlist. Use the Terminal for arbitrary commands.' });
    }

    const { stdout, stderr } = await execAsync(command, { timeout: 30000 });
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: error.stdout || error.stderr || '' });
  }
});

// ============================================================================
// GITHUB ENDPOINTS
// ============================================================================

function sanitizeRepoName(name) {
  if (!name || !/^[\w._-]{1,100}$/.test(name)) throw new Error('Invalid repo name');
  return name;
}

// GitHub API auth
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_AUTH = GITHUB_TOKEN
  ? `-H "Authorization: token ${GITHUB_TOKEN}"`
  : '';

async function githubFetch(url) {
  const { stdout } = await execAsync(`curl -s ${GITHUB_AUTH} "${url}"`, { timeout: 15000 });
  const data = JSON.parse(stdout);
  // Handle rate limiting
  if (data.message && data.documentation_url) {
    if (data.message.includes('rate limit')) {
      throw new Error('GitHub API rate limit exceeded. Add GITHUB_TOKEN to increase limit from 60 to 5000/hr.');
    }
    throw new Error(data.message);
  }
  return data;
}

app.get('/api/github/repos', async (req, res) => {
  try {
    const repos = await githubFetch(`https://api.github.com/users/${GITHUB_USERNAME}/repos?per_page=100&sort=pushed`);
    res.json({ success: true, data: repos });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/commits/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/commits?per_page=20`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/branches/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/branches?per_page=50`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/issues/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const state = req.query.state || 'open';
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/issues?per_page=20&state=${state}`);
    res.json({ success: true, data: data.filter(i => !i.pull_request) });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/pulls/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const state = req.query.state || 'open';
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/pulls?per_page=20&state=${state}`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/releases/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/releases?per_page=10`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/readme/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/readme`);
    // Decode base64 content
    const content = Buffer.from(data.content, 'base64').toString('utf-8');
    res.json({ success: true, data: { ...data, content } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/actions/:repo', async (req, res) => {
  try {
    const repo = sanitizeRepoName(req.params.repo);
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${repo}/actions/runs?per_page=15`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// GIT COMMANDS - SECURED WITH WHITELIST
// ============================================================================

const ALLOWED_GIT_COMMANDS = [
  'git status',
  'git log',
  'git diff',
  'git pull',
  'git fetch',
  'git branch',
  'git checkout',
];

app.post('/api/git/command', async (req, res) => {
  try {
    const { command, cwd } = req.body;

    if (!command || typeof command !== 'string') {
      return res.status(400).json({ success: false, error: 'Command is required' });
    }

    // Validate command against whitelist
    const isAllowed = ALLOWED_GIT_COMMANDS.includes(command) ||
      /^git -C \/var\/www\/[\w._-]{1,100} (status|log|diff|pull|fetch|branch|checkout) .{0,200}$/.test(command) ||
      /^git -C \/var\/www\/[\w._-]{1,100} (status|log|diff|pull|fetch|branch|checkout)$/.test(command);

    if (!isAllowed) {
      return res.status(403).json({ success: false, error: 'Command not in allowlist. Allowed: git status, log, diff, pull, fetch, branch, checkout' });
    }

    const { stdout, stderr } = await execAsync(command, { cwd: cwd || '/var/www', timeout: 30000 });
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: error.stdout || error.stderr });
  }
});

// ============================================================================
// DOCKER ENDPOINTS
// ============================================================================

// Docker container ID validation helper
function validateContainerId(id) {
  if (!id || !/^[a-zA-Z0-9_-]{1,64}$/.test(id)) {
    throw new Error('Invalid container ID. Use alphanumeric, underscores, hyphens only (max 64 chars).');
  }
  return id;
}

app.get('/api/docker/containers', async (req, res) => {
  try {
    const { stdout } = await execAsync('docker ps -a --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}|{{.CreatedAt}}"');
    const containers = stdout.trim().split('\n').filter(Boolean).map(line => {
      const [id, name, image, status, ports, createdAt] = line.split('|');
      return { id, name, image, status, ports, createdAt };
    });
    res.json({ success: true, data: containers });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: [] });
  }
});

app.post('/api/docker/container/:action/:id', async (req, res) => {
  try {
    const { action, id } = req.params;
    const validActions = ['start', 'stop', 'restart', 'pause', 'unpause', 'kill'];
    if (!validActions.includes(action)) {
      return res.status(400).json({ success: false, error: 'Invalid action' });
    }
    const validId = validateContainerId(id);
    await execAsync(`docker ${action} ${validId}`);
    res.json({ success: true });
  } catch (error) {
    if (error.message.includes('Invalid container ID')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/docker/container/:id', async (req, res) => {
  try {
    const validId = validateContainerId(req.params.id);
    await execAsync(`docker rm -f ${validId}`);
    res.json({ success: true });
  } catch (error) {
    if (error.message.includes('Invalid container ID')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/docker/container/:id/inspect', async (req, res) => {
  try {
    const validId = validateContainerId(req.params.id);
    const { stdout } = await execAsync(`docker inspect ${validId}`);
    res.json({ success: true, data: JSON.parse(stdout)[0] });
  } catch (error) {
    if (error.message.includes('Invalid container ID')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/docker/container/:id/stats', async (req, res) => {
  try {
    const validId = validateContainerId(req.params.id);
    const { stdout } = await execAsync(`docker stats ${validId} --no-stream --format "{{json .}}"`);
    res.json({ success: true, data: JSON.parse(stdout.trim()) });
  } catch (error) {
    if (error.message.includes('Invalid container ID')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/docker/images', async (req, res) => {
  try {
    const { stdout } = await execAsync('docker images --format "{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedAt}}"');
    const images = stdout.trim().split('\n').filter(Boolean).map(line => {
      const [id, repository, tag, size, createdAt] = line.split('|');
      return { id, repository, tag, size, createdAt };
    });
    res.json({ success: true, data: images });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: [] });
  }
});

app.delete('/api/docker/image/:id', async (req, res) => {
  try {
    await execAsync(`docker rmi -f ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/docker/pull', (req, res) => {
  const { image } = req.body;
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
  const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  send('start', { image });

  const proc = spawn('docker', ['pull', image]);
  proc.stdout.on('data', d => send('output', { text: d.toString() }));
  proc.stderr.on('data', d => send('output', { text: d.toString(), isStderr: true }));
  proc.on('close', code => send('done', { code }));
});

app.post('/api/docker/run', async (req, res) => {
  try {
    const { image, name, ports, env } = req.body;
    let cmd = ['docker', 'run', '-d'];
    if (name) cmd.push('--name', name);
    if (ports) cmd.push(...ports.split(',').flatMap(p => ['-p', p.trim()]));
    if (env) cmd.push(...env.split(',').flatMap(e => ['-e', e.trim()]));
    cmd.push(image);

    const { stdout } = await execAsync(cmd.join(' '));
    res.json({ success: true, data: stdout.trim() });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/docker/volumes', async (req, res) => {
  try {
    const { stdout } = await execAsync('docker volume ls --format "{{.Driver}}|{{.Name}}|{{.Mountpoint}}"');
    const volumes = stdout.trim().split('\n').filter(Boolean).map(line => {
      const [driver, name, mountpoint] = line.split('|');
      return { driver, name, mountpoint };
    });
    res.json({ success: true, data: volumes });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: [] });
  }
});

app.delete('/api/docker/volume/:name', async (req, res) => {
  try {
    await execAsync(`docker volume rm "${req.params.name}"`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/docker/networks', async (req, res) => {
  try {
    const { stdout } = await execAsync('docker network ls --format "{{.ID}}|{{.Name}}|{{.Driver}}|{{.Scope}}"');
    const networks = stdout.trim().split('\n').filter(Boolean).map(line => {
      const [id, name, driver, scope] = line.split('|');
      return { id, name, driver, scope };
    });
    res.json({ success: true, data: networks });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: [] });
  }
});

app.get('/api/docker/system/df', async (req, res) => {
  try {
    const { stdout } = await execAsync('docker system df --format "{{json .}}"');
    const lines = stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
    res.json({ success: true, data: lines });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/docker/prune', async (req, res) => {
  try {
    const { type } = req.body; // containers, images, volumes, all
    const valid = ['containers', 'images', 'volumes', 'all'];
    if (!valid.includes(type)) return res.status(400).json({ success: false, error: 'Invalid type' });

    const { stdout } = await execAsync(`docker system prune -f${type !== 'all' ? ` --${type}` : ''}`);
    res.json({ success: true, data: stdout });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// SYSTEM STATS
// ============================================================================

async function collectSystemStats() {
  const [cpu1] = os.loadavg();
  await new Promise(r => setTimeout(r, 100));
  const [cpu2] = os.loadavg();

  const mem = os.totalmem();
  const free = os.freemem();
  const used = mem - free;

  const { stdout: disk } = await execAsync('df -h / | tail -1 | awk \'{print $2","$3","$5}\'').catch(() => '0,0,0%');

  const [diskTotal, diskUsed, diskPercent] = disk.trim().split(',');

  return {
    cpu: { current: ((cpu1 + cpu2) / 2 * 100 / os.cpus().length).toFixed(1), load: os.loadavg() },
    memory: { total: mem, used, free, percent: ((used / mem) * 100).toFixed(1) },
    disk: { total: diskTotal, used: diskUsed, percent: diskPercent },
    uptime: os.uptime(),
    timestamp: Date.now(),
  };
}

app.get('/api/system/stats', async (req, res) => {
  try {
    const stats = await collectSystemStats();
    res.json({ success: true, data: stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/system/network', async (req, res) => {
  try {
    const interfaces = os.networkInterfaces();
    const result = Object.entries(interfaces).map(([name, addrs]) => ({
      name,
      addresses: addrs?.map(a => ({ family: a.family, address: a.address, internal: a.internal })) || [],
    }));
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/system/ports', async (req, res) => {
  try {
    const { stdout } = await execAsync('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo ""');
    const lines = stdout.trim().split('\n').slice(1);
    const ports = lines.map(line => {
      const match = line.match(/:(\d+)\s+/);
      return match ? match[1] : null;
    }).filter(Boolean);
    res.json({ success: true, data: [...new Set(ports)] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: [] });
  }
});

// ============================================================================
// DEPLOY PIPELINE — SSE streaming
// ============================================================================

app.post('/api/deploy/pipeline', async (req, res) => {
  const { repo, branch = 'main', port, pm2Name, installCmd = 'npm install --legacy-peer-deps', buildCmd = 'npm run build' } = req.body;

  // Input validation
  if (!repo || !/^[\w._-]{1,100}$/.test(repo)) {
    return res.status(400).json({ success: false, error: 'Invalid repo name. Use alphanumeric, dots, underscores, hyphens.' });
  }
  if (pm2Name && !/^[a-zA-Z0-9_-]{1,100}$/.test(pm2Name res.status(400).json({ success)) {
    return: false, error: 'Invalid PM2 name. Use alphanumeric, underscores, hyphens only.' });
  }
  if (port && (!/^\d+$/.test(port) || parseInt(port) < 1 || parseInt(port) > 65535)) {
    return res.status(400).json({ success: false, error: 'Invalid port number (1-65535).' });
  }
  // Validate install/build commands don't contain dangerous patterns
  if (installCmd && /[;&|`$()]/.test(installCmd)) {
    return res.status(400).json({ success: false, error: 'Install command contains disallowed characters.' });
  }
  if (buildCmd && /[;&|`$()]/.test(buildCmd)) {
    return res.status(400).json({ success: false, error: 'Build command contains disallowed characters.' });
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    if (res.flush) res.flush();
  };

  const runStep = (label, command, cwd) => new Promise((resolve, reject) => {
    send('step-start', { step: label, command });
    const proc = spawn('sh', ['-c', command], { cwd: cwd || '/' });

    proc.stdout.on('data', d => send('output', { text: d.toString(), step: label }));
    proc.stderr.on('data', d => send('output', { text: d.toString(), step: label, isStderr: true }));

    proc.on('exit', code => {
      if (code === 0) { send('step-done', { step: label }); resolve(); }
      else { send('step-error', { step: label, code }); reject(new Error(`${label} exited with code ${code}`)); }
    });
  });

  try {
    const targetDir = `/var/www/${repo}`;

    if (fs.existsSync(targetDir)) {
      await runStep('git-pull', `git pull`, targetDir);
    } else {
      await runStep('clone', `git clone --branch ${branch} --depth 1 https://github.com/${GITHUB_USERNAME}/${repo}.git ${targetDir}`, '/');
    }

    await runStep('install', installCmd, targetDir);

    // Check if build script exists
    const pkgPath = path.join(targetDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg.scripts?.build) {
        await runStep('build', buildCmd, targetDir);
      }
    }

    // Check if already in PM2
    const processes = await getPM2List();
    const existing = processes.find(p => p.name === pm2Name);

    if (existing) {
      await runStep('restart', `pm2 restart "${pm2Name}"`, '/');
    } else {
      // Try ecosystem.config.js first
      const ecoPath = path.join(targetDir, 'ecosystem.config.js');
      if (fs.existsSync(ecoPath)) {
        await runStep('start', `pm2 start ${ecoPath}`, targetDir);
      } else if (fs.existsSync(path.join(targetDir, 'dist'))) {
        await runStep('start', `pm2 start "npx serve dist -l ${port || 3000}" --name "${pm2Name}"`, '/');
      } else if (fs.existsSync(path.join(targetDir, 'package.json'))) {
        await runStep('start', `pm2 start npm --name "${pm2Name}" -- start`, targetDir);
      }
    }

    await runStep('save', 'pm2 save', '/');

    send('complete', { success: true, message: 'Deployment complete!' });
    res.end();
  } catch (error) {
    send('error', { message: error.message });
    res.end();
  }
});

app.post('/api/deploy/clone', async (req, res) => {
  try {
    const { repo, branch = 'main' } = req.body;
    const targetDir = `/var/www/${repo}`;
    if (fs.existsSync(targetDir)) {
      return res.json({ success: false, error: 'Directory already exists' });
    }
    await execAsync(`git clone --branch ${branch} --depth 1 https://github.com/${GITHUB_USERNAME}/${repo}.git ${targetDir}`);
    res.json({ success: true, data: targetDir });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/deploy/build', async (req, res) => {
  try {
    const { cmd, cwd } = req.body;
    const { stdout, stderr } = await execAsync(cmd, { cwd, timeout: 300000 });
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: error.stderr });
  }
});

app.post('/api/deploy/install', async (req, res) => {
  try {
    const { cmd, cwd } = req.body;
    const { stdout, stderr } = await execAsync(cmd, { cwd, timeout: 300000 });
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: error.stderr });
  }
});

// ============================================================================
// SERVER FILES
// ============================================================================

app.get('/api/server/apps', async (req, res) => {
  try {
    const wwwDir = '/var/www';
    if (!fs.existsSync(wwwDir)) return res.json({ success: true, data: [] });

    const entries = fs.readdirSync(wwwDir, { withFileTypes: true });
    const apps = [];

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const appPath = path.join(wwwDir, entry.name);
      const pkgPath = path.join(appPath, 'package.json');
      const distPath = path.join(appPath, 'dist');
      const nextPath = path.join(appPath, '.next');
      const nodeModulesPath = path.join(appPath, 'node_modules');

      let type = 'static';
      if (fs.existsSync(pkgPath)) type = 'node';
      else if (fs.existsSync(nextPath)) type = 'nextjs';
      else if (fs.existsSync(distPath)) type = 'static';

      const ports = [];
      const envLocal = path.join(appPath, '.env.local');
      if (fs.existsSync(envLocal)) {
        const envContent = fs.readFileSync(envLocal, 'utf8');
        const portMatch = envContent.match(/PORT=(\d+)/);
        if (portMatch) ports.push(portMatch[1]);
      }

      apps.push({
        name: entry.name,
        path: appPath,
        type,
        hasPkg: fs.existsSync(pkgPath),
        hasDist: fs.existsSync(distPath),
        hasNext: fs.existsSync(nextPath),
        hasNodeModules: fs.existsSync(nodeModulesPath),
        ports,
      });
    }

    res.json({ success: true, data: apps });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/server/app/:name', async (req, res) => {
  try {
    const { name } = req.params;
    const appPath = `/var/www/${name}`;
    if (!fs.existsSync(appPath)) return res.status(404).json({ error: 'App not found' });

    const pkgPath = path.join(appPath, 'package.json');
    let pkg = null;
    if (fs.existsSync(pkgPath)) {
      pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    }

    res.json({ success: true, data: { name, path: appPath, pkg } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// WEBSOCKET HANDLERS
// ============================================================================

let lastProcessStates = new Map();

wss.on('connection', (ws, request, pathname) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  const dockerId = url.searchParams.get('id');

  // PM2 status updates
  if (pathname === '/ws') {
    const sendPM2Status = async () => {
      try {
        const list = await getPM2List();
        const alerts = [];

        for (const proc of list) {
          const prev = lastProcessStates.get(proc.name);
          if (prev && prev !== proc.status && proc.status === 'errored') {
            alerts.push({ name: proc.name, from: prev, to: proc.status });
          }
          lastProcessStates.set(proc.name, proc.status);
        }

        ws.send(JSON.stringify({ type: 'pm2-list', data: list }));
        if (alerts.length > 0) {
          ws.send(JSON.stringify({ type: 'pm2-alert', data: alerts }));
        }
      } catch {}
    };

    sendPM2Status();
    const interval = setInterval(sendPM2Status, 5000);
    ws.on('close', () => clearInterval(interval));
  }

  // PTY terminal
  else if (pathname === '/ws/terminal' || pathname === '/ws/terminal/') {
    if (!pty) {
      ws.send(JSON.stringify({ type: 'error', data: 'node-pty not available' }));
      ws.close();
      return;
    }

    const shell = process.env.SHELL || '/bin/bash';
    const term = pty.spawn(shell, [], {
      name: 'xterm-color',
      cols: 80,
      rows: 24,
      cwd: process.env.HOME || '/root',
      env: process.env,
    });

    // Docker exec support
    const dockerName = url.searchParams.get('docker');
    if (dockerName) {
      term.kill();
      const dockerPty = pty.spawn('docker', ['exec', '-it', dockerName, '/bin/sh'], {
        name: 'xterm-color',
        cols: 80,
        rows: 24,
        cwd: '/',
        env: process.env,
      });
      term.write = dockerPty.write.bind(dockerPty);
      dockerPty.onData(data => ws.send(JSON.stringify({ type: 'data', data })));
      dockerPty.onExit(() => ws.close());
    } else {
      term.onData(data => ws.send(JSON.stringify({ type: 'data', data })));
    }

    term.onExit(() => ws.close());

    ws.on('message', msg => {
      try {
        const { type, data } = JSON.parse(msg);
        if (type === 'data') term.write(data);
        else if (type === 'resize') {
          term.resize(data.cols, data.rows);
        }
      } catch {}
    });

    ws.on('close', () => term.kill());
  }

  // PM2 logs
  else if (pathname === '/ws/logs') {
    const name = url.searchParams.get('name') || 'all';
    const proc = spawn('tail', ['-f', '-n', '50', `/root/.pm2/logs/${name}-out.log`, `/root/.pm2/logs/${name}-err.log`]);

    proc.stdout.on('data', d => ws.send(JSON.stringify({ type: 'log', data: d.toString(), stream: 'out' })));
    proc.stderr.on('data', d => ws.send(JSON.stringify({ type: 'log', data: d.toString(), stream: 'err' })));

    ws.on('close', () => proc.kill());
  }

  // System stats
  else if (pathname === '/ws/stats') {
    const sendStats = async () => {
      try {
        const stats = await collectSystemStats();
        ws.send(JSON.stringify({ type: 'stats', data: stats }));
      } catch {}
    };

    sendStats();
    const interval = setInterval(sendStats, 2000);
    ws.on('close', () => clearInterval(interval));
  }

  // Docker container logs
  else if (pathname === '/ws/docker') {
    if (!dockerId) {
      ws.send(JSON.stringify({ error: 'Container ID required' }));
      ws.close();
      return;
    }

    const proc = spawn('docker', ['logs', '-f', '--tail', '100', dockerId]);

    proc.stdout.on('data', d => ws.send(JSON.stringify({ type: 'log', data: d.toString(), stream: 'out' })));
    proc.stderr.on('data', d => ws.send(JSON.stringify({ type: 'log', data: d.toString(), stream: 'err' })));

    ws.on('close', () => proc.kill());
  }
});

// ============================================================================
// START SERVER
// ============================================================================

const PORT = process.env.PORT || 3999;
server.listen(PORT, () => {
  console.log(`\n\x1b[32m✓ Deployment Dashboard API running on port ${PORT}\x1b[0m`);
  console.log(`  \x1b[36mhttp://localhost:${PORT}\x1b[0m\n`);
});
