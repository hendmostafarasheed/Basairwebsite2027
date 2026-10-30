import jwt from 'jsonwebtoken';
import { query } from './db.js';
import { config } from './config.js';

export function issueAuthToken(user) {
  return jwt.sign(
    { sub: String(user.id), role: user.role },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn, issuer: 'basair-platform' }
  );
}

export async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'يلزم تسجيل الدخول.' });
    const payload = jwt.verify(token, config.jwtSecret, { issuer: 'basair-platform' });
    const result = await query(
      'SELECT id, full_name, email, role, active FROM users WHERE id = $1',
      [payload.sub]
    );
    const user = result.rows[0];
    if (!user || !user.active) return res.status(401).json({ error: 'الحساب غير متاح.' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'جلسة الدخول غير صالحة أو انتهت.' });
  }
}

export function allowRoles(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'ليست لديك صلاحية لتنفيذ هذا الإجراء.' });
    }
    next();
  };
}
