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
const User = require('./models/User');

dotenv.config();

connectDB();

const app = express();
const server = http.createServer(app);

const allowedOrigins = (process.env.CLIENT_ORIGINS || "")
  .split(",")
  .map(o => o.trim());

app.use(cors({
  origin: function (origin, callback) {
    // Postman, curl kimi origin göndərməyənlər
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("CORS blocked: " + origin));
  },
  credentials: true,
  methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.options("*", cors({
  origin: allowedOrigins,
  credentials: true
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
  process.env.JWT_ACCESS_SECRET;

const wss = new WebSocket.Server({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  (async () => {
    try {
      const url = new URL(req.url, `http://${req.headers.host}`);
      const token = url.searchParams.get('token');

      if (!token) {
        ws.close(4001, 'Token tələb olunur'); // 4001: Unauthorized
        return;
      }

      const decoded = jwt.verify(token, getAccessTokenSecret());

      // İstifadəçini tapırıq
      const user = await User.findById(decoded.id);
      if (!user || !user.isActive) {
        ws.close(4002, 'İstifadəçi aktiv deyil və ya tapılmadı');
        return;
      }

      // Token version yoxlanışı
      const currentVersion = typeof user.tokenVersion === 'number' ? user.tokenVersion : 0;
      if (typeof decoded.tokenVersion !== 'number' || decoded.tokenVersion !== currentVersion) {
        ws.close(4003, 'Sessiya etibarsızdır'); // 4003: Session Invalid
        return;
      }

      ws.user = { id: user._id, email: user.email };
      ws.userId = user._id;

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
        // Burada gələcək mesajları emal edə bilərik
        // Məsələn, ping/pong mexanizmi
        try {
          const parsed = JSON.parse(message);
          if (parsed.type === 'ping') {
             ws.send(JSON.stringify({ type: 'pong' }));
          }
        } catch (e) {
          // JSON olmayan mesajları ignor edirik
        }
      });

      ws.on('close', () => {
        if (ws.userId) {
          onlineUsers.removeOnlineUser(ws.userId);
        }
      });
      
      ws.on('error', (err) => {
          console.error(`WebSocket xətası: ${err.message}`);
          if (ws.userId) {
            onlineUsers.removeOnlineUser(ws.userId);
          }
      });

    } catch (err) {
      if (err.name === 'TokenExpiredError') {
         ws.close(4004, 'Token vaxtı bitib');
      } else {
         ws.close(4002, 'Doğrulama xətası');
      }
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
