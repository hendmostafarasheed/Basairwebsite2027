import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import { config } from './config.js';
import { pool, query } from './db.js';
import { allowRoles, issueAuthToken, requireAuth } from './auth.js';
import { createParticipantToken, roomService } from './livekit.js';

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || config.corsOrigins.length === 0 || config.corsOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '20kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false }));

const roomKeys = new Set(['quran', 'tajweed', 'sharia']);
const roomNames = { quran: 'basair-quran', tajweed: 'basair-tajweed', sharia: 'basair-sharia' };

app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'basair-live-server' }));

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password || email.length > 254 || password.length > 200) {
      return res.status(400).json({ error: 'أدخل البريد الإلكتروني وكلمة المرور.' });
    }
    const result = await query(
      'SELECT id, full_name, email, password_hash, role, active FROM users WHERE email = $1',
      [email]
    );
    const user = result.rows[0];
    if (!user || !user.active || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة.' });
    }
    const token = issueAuthToken(user);
    return res.json({
      token,
      user: { id: user.id, fullName: user.full_name, email: user.email, role: user.role }
    });
  } catch (err) { next(err); }
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: { id: req.user.id, fullName: req.user.full_name, email: req.user.email, role: req.user.role } });
});

// Admin-only: provision accounts and assign permitted rooms. No public self-registration.
app.post('/api/admin/users', requireAuth, allowRoles('admin'), async (req, res, next) => {
  const client = await pool.connect();
  try {
    const { fullName, email, password, role, roomKeys: assignedRooms = [] } = req.body || {};
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!String(fullName || '').trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) ||
        String(password || '').length < 12 || !['teacher', 'student'].includes(role) ||
        !Array.isArray(assignedRooms) || assignedRooms.some(k => !roomKeys.has(k))) {
      return res.status(400).json({ error: 'بيانات الحساب أو الصلاحيات غير مكتملة. كلمة المرور 12 حرفًا على الأقل.' });
    }
    if (role === 'teacher' && assignedRooms.length === 0) {
      return res.status(400).json({ error: 'يجب تخصيص حلقة واحدة على الأقل للمحاضر.' });
    }
    if (role === 'student' && assignedRooms.length !== 1) {
      return res.status(400).json({ error: 'يجب تخصيص الطالب لحلقة واحدة فقط.' });
    }
    await client.query('BEGIN');
    const hash = await bcrypt.hash(password, 12);
    const created = await client.query(
      'INSERT INTO users (full_name,email,password_hash,role) VALUES ($1,$2,$3,$4) RETURNING id,full_name,email,role',
      [String(fullName).trim(), normalizedEmail, hash, role]
    );
    const table = role === 'teacher' ? 'teacher_rooms' : 'student_rooms';
    for (const key of assignedRooms) {
      await client.query(
        `INSERT INTO ${table} (${role}_id, room_id) SELECT $1, id FROM rooms WHERE room_key = $2`,
        [created.rows[0].id, key]
      );
    }
    await client.query('COMMIT');
    const u = created.rows[0];
    res.status(201).json({ user: { id: u.id, fullName: u.full_name, email: u.email, role: u.role }, assignedRooms });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ error: 'البريد الإلكتروني مستخدم بالفعل.' });
    next(err);
  } finally { client.release(); }
});

// List the current user's authorized rooms.
app.get('/api/rooms', requireAuth, async (req, res, next) => {
  try {
    if (req.user.role === 'admin') {
      const r = await query('SELECT room_key AS key, display_name AS name FROM rooms WHERE active = TRUE ORDER BY id');
      return res.json({ rooms: r.rows });
    }
    const table = req.user.role === 'teacher' ? 'teacher_rooms' : 'student_rooms';
    const r = await query(
      `SELECT rooms.room_key AS key, rooms.display_name AS name
       FROM ${table} assignment JOIN rooms ON rooms.id = assignment.room_id
       WHERE assignment.${req.user.role}_id = $1 AND rooms.active = TRUE ORDER BY rooms.id`,
      [req.user.id]
    );
    res.json({ rooms: r.rows });
  } catch (err) { next(err); }
});

// Teacher starts an assigned room. Students cannot call this endpoint.
app.post('/api/teacher/rooms/:roomKey/start', requireAuth, allowRoles('teacher', 'admin'), async (req, res, next) => {
  try {
    const key = req.params.roomKey;
    if (!roomKeys.has(key)) return res.status(404).json({ error: 'الحلقة غير موجودة.' });
    if (req.user.role === 'teacher') {
      const assigned = await query(
        `SELECT 1 FROM teacher_rooms tr JOIN rooms r ON r.id=tr.room_id
         WHERE tr.teacher_id=$1 AND r.room_key=$2 AND r.active=TRUE`,
        [req.user.id, key]
      );
      if (!assigned.rowCount) return res.status(403).json({ error: 'هذه الحلقة ليست ضمن صلاحيات حسابك.' });
    }
    const roomName = roomNames[key];
    try {
      await roomService.createRoom({ name: roomName, emptyTimeout: 10 * 60, maxParticipants: 40 });
    } catch (e) {
      // Room may already exist; LiveKit reports this if a session was created earlier.
      if (!String(e.message || '').toLowerCase().includes('already')) throw e;
    }
    res.json({ roomKey: key, roomName, status: 'ready' });
  } catch (err) { next(err); }
});

// Create short-lived LiveKit access token after server-side role and room checks.
app.post('/api/live/token', requireAuth, async (req, res, next) => {
  try {
    const key = String(req.body?.roomKey || '');
    if (!roomKeys.has(key)) return res.status(400).json({ error: 'اختيار الحلقة غير صحيح.' });
    const roomName = roomNames[key];
    const isAdmin = req.user.role === 'admin';
    const assignmentTable = req.user.role === 'teacher' ? 'teacher_rooms' : 'student_rooms';
    if (!isAdmin) {
      const idColumn = req.user.role === 'teacher' ? 'teacher_id' : 'student_id';
      const assigned = await query(
        `SELECT 1 FROM ${assignmentTable} a JOIN rooms r ON r.id=a.room_id
         WHERE a.${idColumn}=$1 AND r.room_key=$2 AND r.active=TRUE`,
        [req.user.id, key]
      );
      if (!assigned.rowCount) return res.status(403).json({ error: 'غير مسموح لحسابك بدخول هذه الحلقة.' });
    }
    const teacher = req.user.role === 'teacher' || isAdmin;
    if (teacher) {
      const roomCheck = await roomService.listRooms();
      if (!roomCheck.some(r => r.name === roomName)) {
        return res.status(409).json({ error: 'لم يبدأ المحاضر الحلقة بعد.' });
      }
    }
    const token = await createParticipantToken({
      identity: req.user.id,
      name: req.user.full_name,
      roomName,
      canPublish: teacher,
      canSubscribe: true
    });
    res.json({ token, serverUrl: config.livekitUrl, roomName, role: req.user.role });
  } catch (err) { next(err); }
});

// Teacher/admin can mute a participant by identity. Student identities are server-issued DB IDs.
app.post('/api/teacher/rooms/:roomKey/mute', requireAuth, allowRoles('teacher', 'admin'), async (req, res, next) => {
  try {
    const key = req.params.roomKey;
    const identity = String(req.body?.identity || '');
    if (!roomKeys.has(key) || !identity) return res.status(400).json({ error: 'بيانات غير صحيحة.' });
    if (req.user.role === 'teacher') {
      const assigned = await query(
        `SELECT 1 FROM teacher_rooms tr JOIN rooms r ON r.id=tr.room_id
         WHERE tr.teacher_id=$1 AND r.room_key=$2`,
        [req.user.id, key]
      );
      if (!assigned.rowCount) return res.status(403).json({ error: 'ليست لديك صلاحية لهذه الحلقة.' });
    }
    const roomName = roomNames[key];
    const participants = await roomService.listParticipants(roomName);
    if (!participants.some(p => p.identity === identity)) return res.status(404).json({ error: 'المشارك غير موجود.' });
    await roomService.mutePublishedTrack(roomName, identity, req.body?.trackSid, true);
    res.json({ success: true });
  } catch (err) { next(err); }
});


// Teacher can inspect the current participants and their published tracks.
app.get('/api/teacher/rooms/:roomKey/participants', requireAuth, allowRoles('teacher', 'admin'), async (req, res, next) => {
  try {
    const key = req.params.roomKey;
    if (!roomKeys.has(key)) return res.status(404).json({ error: 'الحلقة غير موجودة.' });
    if (req.user.role === 'teacher') {
      const assigned = await query(
        `SELECT 1 FROM teacher_rooms tr JOIN rooms r ON r.id=tr.room_id
         WHERE tr.teacher_id=$1 AND r.room_key=$2`,
        [req.user.id, key]
      );
      if (!assigned.rowCount) return res.status(403).json({ error: 'ليست لديك صلاحية لهذه الحلقة.' });
    }
    const participants = await roomService.listParticipants(roomNames[key]);
    res.json({ participants: participants.map(p => ({
      identity: p.identity, name: p.name,
      tracks: (p.tracks || []).map(t => ({ sid: t.sid, type: t.type, muted: t.muted }))
    })) });
  } catch (err) { next(err); }
});

// Explicitly approve a student's request to publish audio/video.
app.post('/api/teacher/rooms/:roomKey/approve/:identity', requireAuth, allowRoles('teacher', 'admin'), async (req, res, next) => {
  try {
    const key = req.params.roomKey;
    const identity = String(req.params.identity || '');
    if (!roomKeys.has(key) || !identity) return res.status(400).json({ error: 'بيانات غير صحيحة.' });
    if (req.user.role === 'teacher') {
      const assigned = await query(
        `SELECT 1 FROM teacher_rooms tr JOIN rooms r ON r.id=tr.room_id
         WHERE tr.teacher_id=$1 AND r.room_key=$2`,
        [req.user.id, key]
      );
      if (!assigned.rowCount) return res.status(403).json({ error: 'ليست لديك صلاحية لهذه الحلقة.' });
    }
    const student = await query(
      `SELECT 1 FROM student_rooms sr JOIN rooms r ON r.id=sr.room_id
       JOIN users u ON u.id=sr.student_id
       WHERE u.id=$1 AND r.room_key=$2 AND u.active=TRUE`,
      [identity, key]
    );
    if (!student.rowCount) return res.status(404).json({ error: 'الطالب غير مخصص لهذه الحلقة.' });
    await roomService.updateParticipant(roomNames[key], identity, undefined, {
      canPublish: true, canSubscribe: true, canPublishData: true
    });
    res.json({ success: true, identity });
  } catch (err) { next(err); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: config.nodeEnv === 'production' ? 'حدث خطأ بالخادم.' : err.message });
});

const server = app.listen(config.port, () => console.log(`Basair server listening on ${config.port}`));
async function shutdown() {
  server.close();
  await pool.end();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
