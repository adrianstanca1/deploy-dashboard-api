# Deployment Dashboard API

Backend server for the Deployment Dashboard.

## Features

- PM2 process management API
- Real-time WebSocket terminal (node-pty)
- Docker management (containers, images, volumes, networks)
- GitHub API integration
- Deploy pipeline with SSE streaming
- JWT authentication

## Installation

```bash
npm install
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3999 |
| `DASHBOARD_JWT_SECRET` | JWT secret (required in production) | dev secret |
| `DASHBOARD_USER` | Admin username | admin |
| `DASHBOARD_PASSWORD` | Admin password | admin123 |
| `DASHBOARD_GITHUB_USER` | GitHub username | adrianstanca1 |
| `GITHUB_TOKEN` | GitHub token for API rate limit | - |

## Running

```bash
# Production
npm start

# Development
npm run dev
```

## API Endpoints

- `/api/auth/*` - Authentication
- `/api/pm2/*` - PM2 management
- `/api/docker/*` - Docker management
- `/api/github/*` - GitHub integration
- `/api/deploy/*` - Deploy pipeline
- `/api/system/*` - System info
- `/api/server/*` - File browser

## WebSocket Endpoints

- `/ws` - PM2 status updates
- `/ws/terminal` - PTY terminal
- `/ws/logs` - Live logs
- `/ws/stats` - System stats
- `/ws/docker` - Container logs
