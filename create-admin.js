import 'dotenv/config';
import bcrypt from 'bcryptjs';
import { pool, query } from '../src/db.js';

try {
  const name = process.env.BOOTSTRAP_ADMIN_NAME;
  const email = String(process.env.BOOTSTRAP_ADMIN_EMAIL || '').trim().toLowerCase();
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD || '';
  if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 16) {
    throw new Error('Set BOOTSTRAP_ADMIN_NAME, a valid BOOTSTRAP_ADMIN_EMAIL, and BOOTSTRAP_ADMIN_PASSWORD (16+ chars).');
  }
  const hash = await bcrypt.hash(password, 12);
  const result = await query(
    `INSERT INTO users (full_name,email,password_hash,role)
     VALUES ($1,$2,$3,'admin')
     ON CONFLICT (email) DO NOTHING
     RETURNING id,email`,
    [name, email, hash]
  );
  if (!result.rowCount) {
    console.log('Admin email already exists; no account was changed.');
  } else {
    console.log(`Admin account created: ${result.rows[0].email}`);
  }
} finally {
  await pool.end();
}
