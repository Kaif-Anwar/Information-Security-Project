import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { connectDB } from './config/database.js';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.js';
import keyExchangeRoutes from './routes/keyExchange.js';
import messageRoutes from './routes/messages.js';
import fileRoutes from './routes/files.js';

dotenv.config();

// Security: Enforce HTTPS in production
if (process.env.NODE_ENV === 'production') {
  const frontendUrl = process.env.FRONTEND_URL || '';
  if (!frontendUrl.startsWith('https://')) {
    console.error('SECURITY WARNING: FRONTEND_URL must use HTTPS in production!');
  }
  // In production, should use https.createServer instead of http.createServer
  console.warn('SECURITY WARNING: Server should use HTTPS in production. Use https.createServer with SSL certificates.');
}

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3001;

// Middleware
// CORS configuration - allow custom headers for authentication
const corsOptions = {
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true,
  allowedHeaders: ['Content-Type', 'x-user-id', 'X-User-Id', 'Authorization', 'Accept'],
  exposedHeaders: ['x-user-id'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  preflightContinue: false,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

// Handle OPTIONS requests explicitly (CORS preflight)
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/key-exchange', keyExchangeRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/files', fileRoutes);

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log(`✅ Client connected: ${socket.id}`);

  socket.on('disconnect', () => {
    console.log(`⚠️  Client disconnected: ${socket.id}`);
  });
});

// Connect to MongoDB
connectDB();

// Start server
httpServer.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📡 Socket.io ready for connections`);
});

export { app, io };

