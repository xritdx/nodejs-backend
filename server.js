const express = require('express');
const http = require('http');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const connectDB = require('./config/database');
const routes = require('./routes');
const globalErrorHandler = require('./middlewares/errors/globalErrorHandler');
const notFoundHandler = require('./middlewares/errors/notFoundHandler');
const auditMiddleware = require('./middlewares/audit');
const onlineUsers = require('./services/onlineUsers');
const rbacService = require('./services/rbac.service');

dotenv.config();

connectDB();

const app = express();
const server = http.createServer(app);

app.use(cors({
  origin: process.env.CLIENT_ORIGIN || "*",
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"],

}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(auditMiddleware);

app.use('/api', routes);

app.get('/api/health', (req, res) => {
  res.json({ message: 'Server işləyir', status: 'OK' });
});

app.use(globalErrorHandler);
app.use('*', notFoundHandler);

const getAccessTokenSecret = () =>
  process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET;

const wss = new WebSocket.Server({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  (async () => {
    try {
      const url = new URL(req.url, `http://${req.headers.host}`);
      const token = url.searchParams.get('token');

      if (!token) {
        ws.close(4001);
        return;
      }

      const decoded = jwt.verify(token, getAccessTokenSecret());
      ws.user = { id: decoded.id, email: decoded.email };
      ws.userId = decoded.id;

      const permissions = await rbacService.getUserPermissions(ws.userId);
      const slugs = permissions.map(p => p.slug);
      ws.permissions = slugs;
      ws.canSeeUserStatus = slugs.includes('user.read');

      onlineUsers.addOnlineUser(ws.userId);

      ws.send(JSON.stringify({
        type: 'connected',
        userId: decoded.id,
        email: decoded.email,
        canSeeUserStatus: ws.canSeeUserStatus
      }));

      ws.on('message', message => {
        ws.send(JSON.stringify({
          type: 'echo',
          message: message.toString()
        }));
      });

      ws.on('close', () => {
        if (ws.userId) {
          onlineUsers.removeOnlineUser(ws.userId);
        }
      });
    } catch (err) {
      ws.close(4002);
    }
  })();
});

onlineUsers.onStatusChange(({ userId, isOnline }) => {
  const payload = JSON.stringify({
    type: 'userStatusChanged',
    userId,
    isOnline
  });

  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && client.canSeeUserStatus) {
      client.send(payload);
    }
  });
});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Server ${PORT} nömrəli portda işləyir`);
  console.log(`Cari mühit: ${process.env.NODE_ENV}`);
  console.log(`WebSocket /ws endpoint aktivdir`);
});
