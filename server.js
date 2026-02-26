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
const GITHUB_USERNAME = process.env.DASHBOARD_GITHUB_USER || 'adrianstanca1';

if (!process.env.DASHBOARD_JWT_SECRET) {
  console.warn('\x1b[33m⚠ DASHBOARD_JWT_SECRET not set — using insecure default\x1b[0m');
}
if (!process.env.DASHBOARD_PASSWORD) {
  console.warn('\x1b[33m⚠ DASHBOARD_PASSWORD not set — default password is "admin123"\x1b[0m');
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

// Simple in-memory rate limiter for login
const loginAttempts = new Map();
function checkLoginRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + 60_000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 60_000; }
  entry.count++;
  loginAttempts.set(ip, entry);
  return entry.count <= 10;
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  try {
    req.user = verifyToken(header.slice(7));
    next();
  } catch {
    res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
}

const app = express();
const server = http.createServer(app);

// ============================================================================
// WEBSOCKET — multi-path noServer pattern
// ============================================================================

const wssStatus = new WebSocket.Server({ noServer: true });
const wssTerminal = new WebSocket.Server({ noServer: true });
const wssLogs = new WebSocket.Server({ noServer: true });
const wssStats = new WebSocket.Server({ noServer: true });
const wssDockerLogs = new WebSocket.Server({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  const { pathname, searchParams } = new URL(request.url, 'http://localhost');
  const token = searchParams.get('token');
  try {
    verifyToken(token || '');
  } catch {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }

  if (pathname === '/ws') {
    wssStatus.handleUpgrade(request, socket, head, ws => wssStatus.emit('connection', ws, request));
  } else if (pathname.startsWith('/ws/terminal')) {
    wssTerminal.handleUpgrade(request, socket, head, ws => wssTerminal.emit('connection', ws, request));
  } else if (pathname.startsWith('/ws/logs')) {
    wssLogs.handleUpgrade(request, socket, head, ws => wssLogs.emit('connection', ws, request));
  } else if (pathname.startsWith('/ws/stats')) {
    wssStats.handleUpgrade(request, socket, head, ws => wssStats.emit('connection', ws, request));
  } else if (pathname.startsWith('/ws/docker')) {
    wssDockerLogs.handleUpgrade(request, socket, head, ws => wssDockerLogs.emit('connection', ws, request));
  } else {
    socket.destroy();
  }
});

app.use(cors());
app.use(express.json());

// ============================================================================
// PM2 HELPERS
// ============================================================================

async function getPM2List() {
  const { stdout } = await execAsync('pm2 jlist');
  return JSON.parse(stdout).map(p => ({
    name: p.name,
    pid: p.pid,
    status: p.pm2_env?.status || 'unknown',
    cpu: p.monit?.cpu || 0,
    memory: p.monit?.memory || 0,
    uptime: p.pm2_env?.pm_uptime ? Date.now() - p.pm2_env.pm_uptime : 0,
    restarts: p.pm2_env?.restart_time || 0,
  }));
}

// PM2 name validation helper
function validatePM2Name(name) {
  if (!name || !/^[a-zA-Z0-9_-]{1,100}$/.test(name)) {
    throw new Error('Invalid process name. Use alphanumeric, underscores, hyphens only.');
  }
  return name;
}

// ============================================================================
// DOCKER VALIDATION
// ============================================================================

function validateContainerId(id) {
  if (!id || !/^[a-zA-Z0-9_-]{1,64}$/.test(id)) {
    throw new Error('Invalid container ID.');
  }
  return id;
}

// ============================================================================
// AUTH ENDPOINTS
// ============================================================================

app.post('/api/auth/login', async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress;
  if (!checkLoginRateLimit(ip)) {
    return res.status(429).json({ success: false, error: 'Too many attempts. Try again in 1 minute.' });
  }
  const { username, password } = req.body;
  if (username === DASHBOARD_USER && password === DASHBOARD_PASSWORD) {
    const token = jwt.sign({ user: username }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ success: true, token });
  }
  res.status(401).json({ success: false, error: 'Invalid credentials' });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ success: true, user: req.user });
});

// ============================================================================
// PM2 ENDPOINTS
// ============================================================================

app.get('/api/pm2/list', requireAuth, async (req, res) => {
  try {
    const processes = await getPM2List();
    res.json({ success: true, data: processes });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/pm2/status', requireAuth, async (req, res) => {
  try {
    const processes = await getPM2List();
    const counts = { online: 0, stopped: 0, errored: 0 };
    processes.forEach(p => { if (p.status === 'online') counts.online++; else if (p.status === 'errored') counts.errored++; else counts.stopped++; });
    res.json({ success: true, data: counts });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/pm2/logs/:name', requireAuth, async (req, res) => {
  try {
    const name = validatePM2Name(req.params.name);
    const lines = req.query.lines || 200;
    const { stdout, stderr } = await execAsync(`pm2 logs ${name} --lines ${lines} --nostream 2>&1`);
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/restart/:name', requireAuth, async (req, res) => {
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

app.post('/api/pm2/stop/:name', requireAuth, async (req, res) => {
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

app.post('/api/pm2/start/:name', requireAuth, async (req, res) => {
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

app.post('/api/pm2/delete/:name', requireAuth, async (req, res) => {
  try {
    const name = validatePM2Name(req.params.name);
    await execAsync(`pm2 delete "${name}"`);
    res.json({ success: true, message: `Deleted ${name}` });
  } catch (error) {
    if (error.message.includes('Invalid process name')) {
      return res.status(400).json({ success: false, error: error.message });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/bulk', requireAuth, async (req, res) => {
  try {
    const { action, names } = req.body;
    const validActions = ['restart', 'stop', 'start', 'delete'];
    if (!validActions.includes(action)) return res.status(400).json({ success: false, error: 'Invalid action' });

    const results = await Promise.allSettled(
      names.map(name => execAsync(`pm2 ${action} "${name}"`))
    );
    const succeeded = results.filter(r => r.status === 'fulfilled').length;
    res.json({ success: true, data: { succeeded, failed: names.length - succeeded, total: names.length } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/pm2/restart-errored', requireAuth, async (req, res) => {
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

app.post('/api/pm2/save', requireAuth, async (req, res) => {
  try {
    await execAsync('pm2 save');
    res.json({ success: true, message: 'PM2 process list saved' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// SYSTEM EXEC (WHITELISTED)
// ============================================================================

const ALLOWED_COMMANDS = [
  'pm2 save', 'pm2 list', 'nginx -t', 'nginx -s reload', 'nginx -s reopen',
  'df -h', 'free -h', 'uptime', 'who', 'last -n 10', 'netstat -tlnp', 'ss -tlnp',
  'systemctl status nginx', 'systemctl reload nginx', 'systemctl status ssh',
  'journalctl -n 50 --no-pager', 'ps aux --sort=-%cpu | head -20', 'ps aux --sort=-%mem | head -20',
];

app.post('/api/system/exec', requireAuth, async (req, res) => {
  try {
    const { command } = req.body;
    const isAllowed = ALLOWED_COMMANDS.includes(command) ||
      /^pm2 (restart|stop|start|delete|save|jlist|logs) .{0,100}$/.test(command) ||
      /^git -C \/var\/www\/.{1,100} (pull|status|log|diff) .{0,100}$/.test(command);

    if (!isAllowed) {
      return res.status(403).json({ success: false, error: 'Command not in allowlist.' });
    }

    const { stdout, stderr } = await execAsync(command, { timeout: 30000 });
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: error.stdout || error.stderr || '' });
  }
});

// ============================================================================
// GIT COMMANDS - SECURED
// ============================================================================

const ALLOWED_GIT_COMMANDS = ['git status', 'git log', 'git diff', 'git pull', 'git fetch', 'git branch', 'git checkout'];

app.post('/api/git/command', requireAuth, async (req, res) => {
  try {
    const { command, cwd } = req.body;
    if (!command || typeof command !== 'string') {
      return res.status(400).json({ success: false, error: 'Command is required' });
    }

    const isAllowed = ALLOWED_GIT_COMMANDS.includes(command) ||
      /^git -C \/var\/www\/[\w._-]{1,100} (status|log|diff|pull|fetch|branch|checkout) .{0,200}$/.test(command) ||
      /^git -C \/var\/www\/[\w._-]{1,100} (status|log|diff|pull|fetch|branch|checkout)$/.test(command);

    if (!isAllowed) {
      return res.status(403).json({ success: false, error: 'Command not allowed.' });
    }

    const { stdout, stderr } = await execAsync(command, { cwd: cwd || '/var/www', timeout: 30000 });
    res.json({ success: true, data: stdout || stderr });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: error.stdout || error.stderr });
  }
});

// ============================================================================
// GITHUB ENDPOINTS
// ============================================================================

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_AUTH = GITHUB_TOKEN ? `-H "Authorization: token ${GITHUB_TOKEN}"` : '';

async function githubFetch(url) {
  const { stdout } = await execAsync(`curl -s ${GITHUB_AUTH} "${url}"`, { timeout: 15000 });
  const data = JSON.parse(stdout);
  if (data.message && data.documentation_url) {
    if (data.message.includes('rate limit')) {
      throw new Error('GitHub API rate limit exceeded. Add GITHUB_TOKEN.');
    }
    throw new Error(data.message);
  }
  return data;
}

app.get('/api/github/repos', requireAuth, async (req, res) => {
  try {
    const repos = await githubFetch(`https://api.github.com/users/${GITHUB_USERNAME}/repos?per_page=100&sort=pushed`);
    res.json({ success: true, data: repos });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/commits/:repo', requireAuth, async (req, res) => {
  try {
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${req.params.repo}/commits?per_page=20`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/branches/:repo', requireAuth, async (req, res) => {
  try {
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${req.params.repo}/branches?per_page=50`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/issues/:repo', requireAuth, async (req, res) => {
  try {
    const state = req.query.state || 'open';
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${req.params.repo}/issues?per_page=20&state=${state}`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/pulls/:repo', requireAuth, async (req, res) => {
  try {
    const state = req.query.state || 'open';
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${req.params.repo}/pulls?per_page=20&state=${state}`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/releases/:repo', requireAuth, async (req, res) => {
  try {
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${req.params.repo}/releases?per_page=10`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/readme/:repo', requireAuth, async (req, res) => {
  try {
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${req.params.repo}/readme`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/github/actions/:repo', requireAuth, async (req, res) => {
  try {
    const data = await githubFetch(`https://api.github.com/repos/${GITHUB_USERNAME}/${req.params.repo}/actions/runs?per_page=15`);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// DOCKER ENDPOINTS
// ============================================================================

app.get('/api/docker/containers', requireAuth, async (req, res) => {
  try {
    const { stdout } = await execAsync('docker ps -a --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}|{{.CreatedAt}}"');
    const containers = stdout.trim().split('\n').filter(Boolean).map(line => {
      const [id, name, image, status, ports, created] = line.split('|');
      return { id, name, image, status, ports, created };
    });
    res.json({ success: true, data: containers });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: [] });
  }
});

app.get('/api/docker/images', requireAuth, async (req, res) => {
  try {
    const { stdout } = await execAsync('docker images --format "{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedAt}}"');
    const images = stdout.trim().split('\n').filter(Boolean).map(line => {
      const [id, repository, tag, size, created] = line.split('|');
      return { id, repository, tag, size, created };
    });
    res.json({ success: true, data: images });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: [] });
  }
});

app.post('/api/docker/container/:action/:id', requireAuth, async (req, res) => {
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

app.delete('/api/docker/container/:id', requireAuth, async (req, res) => {
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

app.get('/api/docker/container/:id/inspect', requireAuth, async (req, res) => {
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

app.get('/api/docker/container/:id/stats', requireAuth, async (req, res) => {
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

app.get('/api/docker/volumes', requireAuth, async (req, res) => {
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

app.delete('/api/docker/volume/:name', requireAuth, async (req, res) => {
  try {
    await execAsync(`docker volume rm "${req.params.name}"`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/docker/networks', requireAuth, async (req, res) => {
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

app.post('/api/docker/pull', requireAuth, async (req, res) => {
  const { image } = req.body;
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
  const proc = spawn('docker', ['pull', image]);
  proc.stdout.on('data', d => res.write(`data: ${JSON.stringify({ status: d.toString() })}\n\n`));
  proc.stderr.on('data', d => res.write(`data: ${JSON.stringify({ status: d.toString() })}\n\n`));
  proc.on('close', () => res.end());
});

app.post('/api/docker/run', requireAuth, async (req, res) => {
  try {
    const { image, name, ports, env } = req.body;
    let cmd = `docker run -d`;
    if (name) cmd += ` --name ${name}`;
    if (ports) ports.forEach(p => cmd += ` -p ${p}`);
    if (env) env.forEach(e => cmd += ` -e ${e}`);
    cmd += ` ${image}`;
    await execAsync(cmd);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/docker/prune', requireAuth, async (req, res) => {
  try {
    const { type } = req.body;
    await execAsync(`docker ${type} prune -f`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// SYSTEM STATS
// ============================================================================

function collectSystemStats() {
  return new Promise(async (resolve) => {
    try {
      const { stdout: cpu1 } = await execAsync("cat /proc/stat | head -1");
      const [cpubefore] = cpu1.match(/\d+/g).map(Number);
      await new Promise(r => setTimeout(r, 100));
      const { stdout: cpu2 } = await execAsync("cat /proc/stat | head -1");
      const [cpuafter] = cpu2.match(/\d+/g).map(Number);
      const cpuPercent = Math.round((1 - (cpuafter - cpubefore) / (cpuafter || 1)) * 100);

      const { stdout: mem } = await execAsync("free -b | tail -1");
      const [total, used, free] = mem.match(/\d+/g).map(Number);

      const { stdout: disk } = await execAsync("df -B1 / | tail -1");
      const [,,, diskUsed, diskAvail] = disk.match(/\d+/g).map(Number);

      const { stdout: uptime } = await execAsync("cat /proc/uptime");
      const uptimeMs = Math.round(parseFloat(uptime.split(' ')[0]) * 1000);

      const { stdout: load } = await execAsync("cat /proc/loadavg");
      const [load1, load5, load15] = load.split(' ').slice(0, 3).map(Number);

      resolve({ cpu: cpuPercent, memory: { total, used, free }, disk: { used: diskUsed, avail: diskAvail }, uptime: uptimeMs, load: { 1: load1, 5: load5, 15: load15 } });
    } catch { resolve(null); }
  });
}

app.get('/api/system/stats', requireAuth, async (req, res) => {
  try {
    const stats = await collectSystemStats();
    res.json({ success: true, data: stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/system/network', requireAuth, async (req, res) => {
  try {
    const { stdout } = await execAsync("ip -j addr show | jq -r '.[] | .addr_info[] | select(.family == \" inet\") | {name: .ifname, ip: .local}'");
    res.json({ success: true, data: JSON.parse(`[${stdout.trim().split('\n').join(',')}]`) });
  } catch {
    res.json({ success: true, data: [] });
  }
});

app.get('/api/system/ports', requireAuth, async (req, res) => {
  try {
    const { stdout } = await execAsync("ss -tlnp | tail -n +2 | awk '{print $4\":\"$6}'");
    const ports = stdout.trim().split('\n').map(l => {
      const [addr, pid] = l.split(':');
      return { address: addr, pid };
    }).filter(p => p.address?.includes(':'));
    res.json({ success: true, data: ports });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// DEPLOY PIPELINE
// ============================================================================

app.post('/api/deploy/pipeline', requireAuth, async (req, res) => {
  const { repo, branch = 'main', port, pm2Name, installCmd = 'npm install --legacy-peer-deps', buildCmd = 'npm run build' } = req.body;

  if (!repo || !/^[\w._-]{1,100}$/.test(repo)) {
    return res.status(400).json({ success: false, error: 'Invalid repo name.' });
  }
  if (pm2Name && !/^[a-zA-Z0-9_-]{1,100}$/.test(pm2Name)) {
    return res.status(400).json({ success: false, error: 'Invalid PM2 name.' });
  }
  if (port && (!/^\d+$/.test(port) || parseInt(port) < 1 || parseInt(port) > 65535)) {
    return res.status(400).json({ success: false, error: 'Invalid port.' });
  }
  if (installCmd && /[;&|`$()]/.test(installCmd)) {
    return res.status(400).json({ success: false, error: 'Install command contains disallowed characters.' });
  }
  if (buildCmd && /[;&|`$()]/.test(buildCmd)) {
    return res.status(400).json({ success: false, error: 'Build command contains disallowed characters.' });
  }

  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });

  const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

  const runStep = (label, command, cwd) => new Promise((resolve, reject) => {
    send('step-start', { step: label, command });
    const proc = spawn('sh', ['-c', command], { cwd: cwd || '/' });
    proc.stdout.on('data', d => send('output', { text: d.toString(), step: label }));
    proc.stderr.on('data', d => send('output', { text: d.toString(), step: label, isStderr: true }));
    proc.on('exit', code => {
      if (code === 0) { send('step-done', { step: label }); resolve(); }
      else { send('step-error', { step: label, code }); reject(new Error(`${label} failed`)); }
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

    const pkgPath = path.join(targetDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg.scripts?.build) {
        await runStep('build', buildCmd, targetDir);
      }
    }

    const processes = await getPM2List();
    const existing = processes.find(p => p.name === pm2Name);
    if (existing) {
      await runStep('restart', `pm2 restart ${pm2Name}`, '/');
    } else {
      await runStep('start', `pm2 start ${targetDir}/ecosystem.config.js || pm2 start npm --name ${pm2Name} -- start`, '/');
    }

    await runStep('save', 'pm2 save', '/');
    send('done', { success: true });
    res.end();
  } catch (error) {
    send('error', { message: error.message });
    res.end();
  }
});

// ============================================================================
// SERVER FILE BROWSER
// ============================================================================

app.get('/api/server/apps', requireAuth, async (req, res) => {
  try {
    const apps = [];
    const dirs = fs.readdirSync('/var/www');
    for (const dir of dirs) {
      const fullPath = path.join('/var/www', dir);
      if (fs.statSync(fullPath).isDirectory()) {
        const hasPackage = fs.existsSync(path.join(fullPath, 'package.json'));
        const hasDist = fs.existsSync(path.join(fullPath, 'dist')) || fs.existsSync(path.join(fullPath, '.next'));
        apps.push({ name: dir, hasPackage, hasDist });
      }
    }
    res.json({ success: true, data: apps });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: [] });
  }
});

app.get('/api/server/app/:name', requireAuth, async (req, res) => {
  try {
    const fullPath = path.join('/var/www', req.params.name);
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ success: false, error: 'App not found' });
    }
    const pkgPath = path.join(fullPath, 'package.json');
    let packageJson = null;
    if (fs.existsSync(pkgPath)) {
      packageJson = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    }
    res.json({ success: true, data: { name: req.params.name, package: packageJson, path: fullPath } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// WEBSOCKET HANDLERS
// ============================================================================

let lastProcessStates = new Map();

wssStatus.on('connection', async (ws) => {
  const send = (type, data) => ws.send(JSON.stringify({ type, data }));
  const interval = setInterval(async () => {
    try {
      const processes = await getPM2List();
      const alerts = [];
      processes.forEach(proc => {
        const prev = lastProcessStates.get(proc.name);
        if (prev === 'errored' && proc.status !== 'errored') { /* recovered */ }
        if (prev !== 'errored' && proc.status === 'errored') { alerts.push({ name: proc.name, from: prev }); }
        lastProcessStates.set(proc.name, proc.status);
      });
      send('pm2-status', processes);
      if (alerts.length) send('pm2-alert', alerts);
    } catch { /* ignore */ }
  }, 3000);
  ws.on('close', () => clearInterval(interval));
});

wssTerminal.on('connection', async (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const dockerId = url.searchParams.get('docker');
  const shell = dockerId ? `docker exec -it ${dockerId} /bin/sh` : process.env.SHELL || '/bin/bash';

  if (!pty) {
    ws.send(JSON.stringify({ type: 'error', data: 'node-pty not available' }));
    ws.close();
    return;
  }

  const term = pty.spawn(shell, [], { name: 'xterm-256color', cols: 80, rows: 24, cwd: process.env.HOME || '/' });
  ws.on('message', data => term.write(data.toString()));
  term.on('data', data => ws.send(data));
  term.on('exit', () => ws.close());
  ws.on('close', () => term.kill());
});

wssLogs.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const name = url.searchParams.get('name') || 'all';
  const proc = spawn('tail', ['-f', `-n`, '50', name === 'all' ? '/var/log/pm2.log' : `/var/log/supervisor/${name}.log`], { shell: true });
  proc.stdout.on('data', d => ws.send(d.toString()));
  proc.stderr.on('data', d => ws.send(d.toString()));
  ws.on('close', () => proc.kill());
});

wssStats.on('connection', async (ws) => {
  const send = async () => {
    const stats = await collectSystemStats();
    ws.send(JSON.stringify(stats));
  };
  send();
  const interval = setInterval(send, 2000);
  ws.on('close', () => clearInterval(interval));
});

wssDockerLogs.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const id = url.searchParams.get('id');
  if (!id) { ws.close(); return; }
  const proc = spawn('docker', ['logs', '-f', '--tail', '50', id]);
  proc.stdout.on('data', d => ws.send(d.toString()));
  proc.stderr.on('data', d => ws.send(d.toString()));
  ws.on('close', () => proc.kill());
});

// ============================================================================
// START SERVER
// ============================================================================

const PORT = process.env.PORT || 3999;
server.listen(PORT, () => {
  console.log(`\x1b[32m✓ Dashboard API running on http://localhost:${PORT}\x1b[0m`);
});