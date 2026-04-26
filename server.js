/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║       JEEVANLINK — BACKEND SERVER                           ║
 * ║       Node.js + Express + Socket.io + JWT Auth              ║
 * ║                                                              ║
 * ║  ENDPOINTS:                                                  ║
 * ║  POST /api/auth/register   — Create account                  ║
 * ║  POST /api/auth/login      — Login, get JWT token            ║
 * ║  GET  /api/me              — Get current user (protected)    ║
 * ║  POST /api/sos/trigger     — Trigger SOS (protected)         ║
 * ║  POST /api/sos/cancel      — Cancel active SOS (protected)   ║
 * ║  GET  /api/hospitals       — List nearby hospitals            ║
 * ║  GET  /api/volunteers      — List nearby volunteers           ║
 * ║  GET  /api/incidents       — Get user's incident history     ║
 * ║  POST /api/location        — Update user location (protected)║
 * ║  WS   Socket.io            — Real-time SOS & alerts          ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * INSTALL:  npm install express bcryptjs jsonwebtoken socket.io cors uuid
 * RUN:      node server.js
 * PORT:     3000
 */

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const { v4: uuidv4 } = require('uuid');
const path       = require('path');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'jeevanlink-super-secret-key-change-in-prod';
const JWT_EXPIRES = '7d';

/* ══════════════════════════════════════════
   IN-MEMORY DATABASE (Replace with MongoDB / PostgreSQL in prod)
══════════════════════════════════════════ */
const DB = {
  users: [
    {
      id: 'usr-demo-1',
      email: 'vipin@jeevanlink.in',
      passwordHash: bcrypt.hashSync('vipin123', 10),
      name: 'vipin narwat ',
      phone: '+91 98100 00000',
      city: 'New Delhi',
      initials: 'v',
      role: 'civilian',
      createdAt: new Date().toISOString(),
      location: { lat: 28.6315, lng: 77.2167, address: 'Connaught Place, New Delhi' },
      family: [
        { name: 'Anita Kapoor', phone: '+91 98100 00001', relation: 'Mother', status: 'online' },
        { name: 'Ramesh Kapoor', phone: '+91 98100 00002', relation: 'Father', status: 'offline' },
        { name: 'Vivek Kapoor', phone: '+91 98100 00003', relation: 'Brother', status: 'notified' },
      ]
    },
    {
      id: 'usr-demo-2',
      email: 'vipin2@jeevanlink.in',
      passwordHash: bcrypt.hashSync('password123', 10),
      name: 'Dr. vipin ',
      phone: '+91 98100 11111',
      city: 'South Delhi',
      initials: 'PM',
      role: 'volunteer',
      skills: ['Registered Nurse', 'First Aid', 'CPR'],
      createdAt: new Date().toISOString(),
      location: { lat: 28.6200, lng: 77.2100, address: 'South Extension, Delhi' },
      family: []
    }
  ],

  incidents: [],

  hospitals: [
    { id: 'h1', name: 'AIIMS New Delhi', distance: 2.1, icuBeds: 12, emergencyOpen: true, capacity: 45, hasTrauma: true, lat: 28.5672, lng: 77.2100 },
    { id: 'h2', name: 'Ram Manohar Lohia Hospital', distance: 3.4, icuBeds: 8, emergencyOpen: true, capacity: 62, hasTrauma: false, lat: 28.6400, lng: 77.1980 },
    { id: 'h3', name: 'Safdarjung Hospital', distance: 4.7, icuBeds: 3, emergencyOpen: true, capacity: 88, hasTrauma: false, lat: 28.5680, lng: 77.2040 },
    { id: 'h4', name: 'Sir Ganga Ram Hospital', distance: 5.2, icuBeds: 15, emergencyOpen: true, capacity: 35, hasTrauma: true, lat: 28.6420, lng: 77.1950 },
    { id: 'h5', name: 'Fortis Escorts Heart Institute', distance: 7.1, icuBeds: 20, emergencyOpen: true, capacity: 55, hasTrauma: true, lat: 28.5500, lng: 77.2600 },
  ],

  volunteers: [
    { id: 'v1', name: 'Rajan Kumar', initials: 'RK', skills: ['First Aid', 'CPR'], distance: 0.4, eta: '~2 min', verified: true, responseCount: 12, lat: 28.6340, lng: 77.2180 },
    { id: 'v2', name: 'Dr. Priya Menon', initials: 'PM', skills: ['Registered Nurse'], distance: 0.9, eta: '~4 min', verified: true, responseCount: 28, lat: 28.6280, lng: 77.2130 },
    { id: 'v3', name: 'Arjun Sharma', initials: 'AS', skills: ['Emergency Doctor'], distance: 1.2, eta: '~5 min', verified: true, responseCount: 45, lat: 28.6250, lng: 77.2200 },
    { id: 'v4', name: 'Divya Verma', initials: 'DV', skills: ['Paramedic'], distance: 1.8, eta: '~7 min', verified: true, responseCount: 19, lat: 28.6380, lng: 77.2250 },
    { id: 'v5', name: 'Rohan Mehta', initials: 'RM', skills: ['First Aid', 'Trauma'], distance: 2.1, eta: '~9 min', verified: true, responseCount: 7, lat: 28.6300, lng: 77.2300 },
  ]
};

/* ══════════════════════════════════════════
   MIDDLEWARE
══════════════════════════════════════════ */
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // Serve frontend

// Auth middleware
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = DB.users.find(u => u.id === decoded.id);
    if (!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/* ══════════════════════════════════════════
   AUTH ROUTES
══════════════════════════════════════════ */
// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name, phone, city } = req.body;
  if (!email || !password || !name || !phone || !city) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (DB.users.find(u => u.email === email)) {
    return res.status(409).json({ error: 'Email already registered' });
  }
  const user = {
    id: 'usr-' + uuidv4(),
    email,
    passwordHash: await bcrypt.hash(password, 10),
    name, phone, city,
    initials: name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2),
    role: 'civilian',
    createdAt: new Date().toISOString(),
    location: null,
    family: []
  };
  DB.users.push(user);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  res.status(201).json({ token, user: sanitizeUser(user) });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = DB.users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  res.json({ token, user: sanitizeUser(user) });
});

// GET /api/me
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: sanitizeUser(req.user) });
});

/* ══════════════════════════════════════════
   SOS ROUTES
══════════════════════════════════════════ */
// POST /api/sos/trigger
app.post('/api/sos/trigger', requireAuth, (req, res) => {
  const { type = 'tap', location } = req.body;
  const incident = {
    id: 'INC-' + Math.floor(1000 + Math.random() * 9000),
    userId: req.user.id,
    userName: req.user.name,
    type,
    location: location || req.user.location,
    status: 'active',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    timeline: [
      { step: 'location_locked', time: new Date().toISOString(), status: 'done' },
    ],
    volunteersAlerted: DB.volunteers.map(v => v.id),
    hospitalRecommended: DB.hospitals.find(h => h.icuBeds > 0 && h.emergencyOpen)
  };
  DB.incidents.push(incident);

  // Simulate timeline progression
  let step = 1;
  const steps = ['volunteers_alerted', 'hospital_check', 'family_notified', 'help_en_route'];
  const stInterval = setInterval(() => {
    if (step >= steps.length) { clearInterval(stInterval); return; }
    incident.timeline.push({ step: steps[step], time: new Date().toISOString(), status: 'done' });
    incident.updatedAt = new Date().toISOString();
    // Broadcast via socket
    io.emit('incident:update', { incidentId: incident.id, step: steps[step], incident });
    step++;
  }, 2000);

  // Broadcast SOS to all connected sockets
  io.emit('sos:triggered', {
    incidentId: incident.id,
    userName: req.user.name,
    location: incident.location,
    volunteersAlerted: incident.volunteersAlerted.length,
    hospital: incident.hospitalRecommended?.name
  });

  res.status(201).json({ incident });
});

// POST /api/sos/cancel
app.post('/api/sos/cancel', requireAuth, (req, res) => {
  const { incidentId } = req.body;
  const incident = DB.incidents.find(i => i.id === incidentId && i.userId === req.user.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  incident.status = 'cancelled';
  incident.updatedAt = new Date().toISOString();
  io.emit('sos:cancelled', { incidentId, userName: req.user.name });
  res.json({ success: true, incident });
});

/* ══════════════════════════════════════════
   DATA ROUTES
══════════════════════════════════════════ */
// GET /api/hospitals — AI-sorted by suitability
app.get('/api/hospitals', requireAuth, (req, res) => {
  const sorted = [...DB.hospitals]
    .filter(h => h.emergencyOpen)
    .sort((a, b) => {
      // Score: distance weight 30%, capacity weight 40%, ICU beds 30%
      const scoreA = (a.icuBeds * 0.3) - (a.distance * 0.3) - (a.capacity * 0.004);
      const scoreB = (b.icuBeds * 0.3) - (b.distance * 0.3) - (b.capacity * 0.004);
      return scoreB - scoreA;
    })
    .map((h, i) => ({ ...h, rank: i + 1 }));
  res.json({ hospitals: sorted });
});

// GET /api/volunteers
app.get('/api/volunteers', requireAuth, (req, res) => {
  res.json({ volunteers: DB.volunteers, total: DB.volunteers.length });
});

// GET /api/incidents — user's history
app.get('/api/incidents', requireAuth, (req, res) => {
  const incidents = DB.incidents
    .filter(i => i.userId === req.user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ incidents });
});

// POST /api/location — update location
app.post('/api/location', requireAuth, (req, res) => {
  const { lat, lng, address } = req.body;
  if (!lat || !lng) return res.status(400).json({ error: 'lat and lng required' });
  req.user.location = { lat, lng, address: address || `${lat.toFixed(4)}, ${lng.toFixed(4)}` };
  // Broadcast location update to family (in real app, only to authorized family)
  io.to(`family:${req.user.id}`).emit('location:update', {
    userId: req.user.id,
    name: req.user.name,
    location: req.user.location
  });
  res.json({ success: true, location: req.user.location });
});

/* ══════════════════════════════════════════
   HEALTH CHECK
══════════════════════════════════════════ */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'operational',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    users: DB.users.length,
    activeIncidents: DB.incidents.filter(i => i.status === 'active').length
  });
});

// Fallback to frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
/* ══════════════════════════════════════════
   SOCKET.IO — Real-time
══════════════════════════════════════════ */
io.on('connection', (socket) => {
  console.log(`[Socket] Connected: ${socket.id}`);

  socket.on('auth', ({ token }) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = DB.users.find(u => u.id === decoded.id);
      if (user) {
        socket.userId = user.id;
        socket.join(`user:${user.id}`);
        socket.emit('auth:success', { userId: user.id, name: user.name });
        console.log(`[Socket] Authenticated: ${user.name}`);
      }
    } catch (e) {
      socket.emit('auth:error', { message: 'Invalid token' });
    }
  });

  socket.on('location:update', ({ lat, lng, address }) => {
    if (!socket.userId) return;
    const user = DB.users.find(u => u.id === socket.userId);
    if (user) {
      user.location = { lat, lng, address };
      // Broadcast to family watchers
      io.to(`family:${user.id}`).emit('location:update', { userId: user.id, name: user.name, location: user.location });
    }
  });

  socket.on('watch:user', ({ targetUserId }) => {
    // Family member watching someone's location
    socket.join(`family:${targetUserId}`);
    socket.emit('watch:confirmed', { targetUserId });
  });

  socket.on('disconnect', () => {
    console.log(`[Socket] Disconnected: ${socket.id}`);
  });
});

/* ══════════════════════════════════════════
   HELPERS
══════════════════════════════════════════ */
function sanitizeUser(user) {
  const { passwordHash, ...safe } = user;
  return safe;
}

/* ══════════════════════════════════════════
   START SERVER
══════════════════════════════════════════ */
server.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║     JeevanLink Server Running        ║
  ║     http://localhost:${PORT}           ║
  ║                                      ║
  ║  Demo Users:                         ║
  ║  vipin@jeevanlink.in / vipin123   ║
  ║  sahil@jeevanlink.in / sahil123   ║
  ╚══════════════════════════════════════╝
  `);
});

module.exports = { app, server, io, DB };