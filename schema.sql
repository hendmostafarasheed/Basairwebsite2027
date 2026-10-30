CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','teacher','student')),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rooms (
  id BIGSERIAL PRIMARY KEY,
  room_key TEXT NOT NULL UNIQUE CHECK (room_key IN ('quran','tajweed','sharia')),
  display_name TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS teacher_rooms (
  teacher_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  room_id BIGINT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  PRIMARY KEY (teacher_id, room_id)
);

CREATE TABLE IF NOT EXISTS student_rooms (
  student_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  room_id BIGINT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  PRIMARY KEY (student_id, room_id)
);

INSERT INTO rooms (room_key, display_name) VALUES
 ('quran', 'تحفيظ القرآن'),
 ('tajweed', 'التجويد والتلاوة'),
 ('sharia', 'العلوم الشرعية')
ON CONFLICT (room_key) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_student_rooms_room ON student_rooms(room_id);
