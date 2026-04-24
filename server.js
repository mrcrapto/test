const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'speech-karaoke-jwt-secret-change-in-production';
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY || '';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const DEEPGRAM_API_KEY = process.env.DEEPGRAM_API_KEY || '';
const MAX_DAYS = 20; // 100 sentences per level / 5 per day = 20 days (~3 weeks)
const SENTENCES_PER_DAY = 5;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Explicit root routes in case static middleware path resolution fails
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ─── DATABASE SETUP ───────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'karaoke.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'student',
    start_date TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    day_number INTEGER NOT NULL,
    level INTEGER NOT NULL,
    sentence_idx INTEGER NOT NULL,
    score REAL NOT NULL DEFAULT 0,
    passed INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 1,
    played_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Seed admin account
const adminExists = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
if (!adminExists) {
  const hash = bcrypt.hashSync('Admin@123', 10);
  db.prepare("INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, 'admin')")
    .run('admin@speechkaraoke.com', 'admin', hash);
  console.log('✅ Default admin created  →  username: admin  |  password: Admin@123');
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
  });
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function getDayNumber(startDate) {
  if (!startDate) return 1;
  const msPerDay = 1000 * 60 * 60 * 24;
  const diff = Math.floor((Date.now() - new Date(startDate).getTime()) / msPerDay);
  return Math.max(1, Math.min(diff + 1, MAX_DAYS));
}

function getSentencesForDay(level, dayNumber) {
  const bank = SENTENCE_BANK[level];
  const start = (dayNumber - 1) * SENTENCES_PER_DAY;
  return bank.slice(start, start + SENTENCES_PER_DAY);
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
app.post('/api/auth/register', (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password)
    return res.status(400).json({ error: 'Email, username, and password are required' });

  const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRx.test(email))
    return res.status(400).json({ error: 'Please enter a valid email address' });

  if (username.length < 3 || username.length > 30)
    return res.status(400).json({ error: 'Username must be 3–30 characters' });

  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Username may only contain letters, numbers, and underscores' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const today = new Date().toISOString().split('T')[0];
    db.prepare("INSERT INTO users (email, username, password_hash, start_date) VALUES (?, ?, ?, ?)")
      .run(email.toLowerCase().trim(), username.trim(), hash, today);

    const user = db.prepare("SELECT id, email, username, role, start_date FROM users WHERE email = ?")
      .get(email.toLowerCase().trim());
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      if (e.message.includes('email')) return res.status(409).json({ error: 'This email is already registered' });
      if (e.message.includes('username')) return res.status(409).json({ error: 'This username is already taken' });
    }
    console.error(e);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required' });

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid username or password' });

  // Set start_date on first login if missing
  if (!user.start_date) {
    const today = new Date().toISOString().split('T')[0];
    db.prepare("UPDATE users SET start_date = ? WHERE id = ?").run(today, user.id);
    user.start_date = today;
  }

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  const { password_hash, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email.toLowerCase().trim());
  if (user) {
    // Invalidate old tokens
    db.prepare("UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0").run(user.id);

    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
    db.prepare("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)")
      .run(user.id, token, expires);

    console.log(`\n🔑 Password reset token for "${user.username}" (${user.email}):\n   ${token}\n`);
    // In production: send token via email. For demo we return it directly.
    return res.json({
      message: 'Reset code generated successfully.',
      resetToken: token, // DEMO ONLY — remove in production
      note: 'In production this would be sent to your email'
    });
  }
  res.json({ message: 'If this email exists, a reset code has been sent.' });
});

app.post('/api/auth/reset-password', (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword)
    return res.status(400).json({ error: 'Token and new password are required' });
  if (newPassword.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const reset = db.prepare(
    "SELECT * FROM password_resets WHERE token = ? AND used = 0 AND expires_at > datetime('now')"
  ).get(token);

  if (!reset) return res.status(400).json({ error: 'Invalid or expired reset token' });

  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, reset.user_id);
  db.prepare("UPDATE password_resets SET used = 1 WHERE id = ?").run(reset.id);
  res.json({ message: 'Password reset successfully. You can now log in.' });
});

// ─── USER ROUTES ─────────────────────────────────────────────────────────────
app.get('/api/user/profile', authMiddleware, (req, res) => {
  const user = db.prepare("SELECT id, email, username, role, start_date, created_at FROM users WHERE id = ?")
    .get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const dayNumber = getDayNumber(user.start_date);
  const stats = db.prepare("SELECT COUNT(*) as total, SUM(passed) as passed, AVG(score) as avgScore FROM results WHERE user_id = ?")
    .get(req.user.id);

  res.json({
    ...user,
    dayNumber,
    maxDays: MAX_DAYS,
    totalPracticed: stats.total || 0,
    totalPassed: stats.passed || 0,
    avgScore: Math.round((stats.avgScore || 0) * 100)
  });
});

app.get('/api/user/today', authMiddleware, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const dayNumber = getDayNumber(user.start_date);

  // Get already-passed sentences today per level
  const doneRows = db.prepare(
    "SELECT level, sentence_idx FROM results WHERE user_id = ? AND day_number = ? AND passed = 1"
  ).all(req.user.id, dayNumber);

  const doneSets = { 1: new Set(), 2: new Set(), 3: new Set(), 4: new Set(), 5: new Set() };
  doneRows.forEach(r => doneSets[r.level].add(r.sentence_idx));

  const todaySentences = {};
  for (let lv = 1; lv <= 5; lv++) {
    const startIdx = (dayNumber - 1) * SENTENCES_PER_DAY;
    const sentences = getSentencesForDay(lv, dayNumber);
    todaySentences[lv] = sentences.map((text, i) => ({
      idx: startIdx + i,
      text,
      done: doneSets[lv].has(startIdx + i)
    }));
  }

  res.json({ dayNumber, maxDays: MAX_DAYS, sentences: todaySentences });
});

app.post('/api/user/submit', authMiddleware, (req, res) => {
  const { level, sentenceIdx, dayNumber, score, passed, attempts } = req.body;
  if (level == null || sentenceIdx == null || dayNumber == null)
    return res.status(400).json({ error: 'Missing required fields' });

  // If already passed this sentence on this day, don't overwrite
  const existing = db.prepare(
    "SELECT id FROM results WHERE user_id = ? AND day_number = ? AND level = ? AND sentence_idx = ? AND passed = 1"
  ).get(req.user.id, dayNumber, level, sentenceIdx);

  if (existing) return res.json({ message: 'Already recorded as passed' });

  db.prepare(
    "INSERT INTO results (user_id, day_number, level, sentence_idx, score, passed, attempts) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(req.user.id, dayNumber, level, sentenceIdx, score || 0, passed ? 1 : 0, attempts || 1);

  res.json({ message: 'Result saved successfully' });
});

// ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────
app.get('/api/admin/students', adminMiddleware, (req, res) => {
  const students = db.prepare(
    "SELECT id, email, username, start_date, created_at FROM users WHERE role = 'student' ORDER BY created_at DESC"
  ).all();

  const enriched = students.map(s => {
    const stats = db.prepare(
      "SELECT COUNT(*) as total, SUM(passed) as passed, AVG(score) as avgScore FROM results WHERE user_id = ?"
    ).get(s.id);
    const daysDone = db.prepare(
      "SELECT COUNT(DISTINCT day_number) as days FROM results WHERE user_id = ? AND passed = 1"
    ).get(s.id);
    return {
      ...s,
      dayNumber: getDayNumber(s.start_date),
      totalPracticed: stats.total || 0,
      totalPassed: stats.passed || 0,
      avgScore: Math.round((stats.avgScore || 0) * 100),
      activeDays: daysDone.days || 0
    };
  });

  res.json(enriched);
});

app.get('/api/admin/student/:id', adminMiddleware, (req, res) => {
  const student = db.prepare(
    "SELECT id, email, username, start_date, created_at FROM users WHERE id = ? AND role = 'student'"
  ).get(req.params.id);
  if (!student) return res.status(404).json({ error: 'Student not found' });

  const results = db.prepare(
    "SELECT * FROM results WHERE user_id = ? ORDER BY played_at DESC LIMIT 200"
  ).all(req.params.id);

  // Per-level stats
  const levelStats = {};
  for (let lv = 1; lv <= 5; lv++) {
    const ls = db.prepare(
      "SELECT COUNT(*) as total, SUM(passed) as passed, AVG(score) as avgScore FROM results WHERE user_id = ? AND level = ?"
    ).get(req.params.id, lv);
    levelStats[lv] = {
      total: ls.total || 0,
      passed: ls.passed || 0,
      avgScore: Math.round((ls.avgScore || 0) * 100)
    };
  }

  // Per-day summary
  const dailySummary = db.prepare(
    "SELECT day_number, COUNT(*) as total, SUM(passed) as passed FROM results WHERE user_id = ? GROUP BY day_number ORDER BY day_number"
  ).all(req.params.id);

  const overallStats = db.prepare(
    "SELECT COUNT(*) as total, SUM(passed) as passed, AVG(score) as avgScore FROM results WHERE user_id = ?"
  ).get(req.params.id);

  res.json({
    ...student,
    dayNumber: getDayNumber(student.start_date),
    maxDays: MAX_DAYS,
    results,
    levelStats,
    dailySummary,
    overallStats: {
      total: overallStats.total || 0,
      passed: overallStats.passed || 0,
      avgScore: Math.round((overallStats.avgScore || 0) * 100)
    }
  });
});

// Delete a student (admin only)
app.delete('/api/admin/student/:id', adminMiddleware, (req, res) => {
  db.prepare("DELETE FROM users WHERE id = ? AND role = 'student'").run(req.params.id);
  res.json({ message: 'Student deleted' });
});

// ─── TRANSCRIPTION (Deepgram → Groq → OpenAI fallback chain) ──────────────────
app.post('/api/transcribe', authMiddleware, async (req, res) => {
  const { audioBase64, mimeType } = req.body;
  if (!audioBase64) return res.status(400).json({ error: 'Missing audioBase64' });

  if (!DEEPGRAM_API_KEY && !GROQ_API_KEY && !OPENAI_API_KEY) {
    return res.status(503).json({
      error: 'No transcription API key configured. Add DEEPGRAM_API_KEY, GROQ_API_KEY, or OPENAI_API_KEY in Railway Variables.'
    });
  }

  try {
    const buffer = Buffer.from(audioBase64, 'base64');
    const contentType = mimeType || 'audio/webm';

    // ── Option A: Deepgram (free $200 credit, very fast) ──
    if (DEEPGRAM_API_KEY) {
      const response = await fetch(
        'https://api.deepgram.com/v1/listen?model=nova-2&language=en&smart_format=true&punctuate=true',
        {
          method: 'POST',
          headers: {
            'Authorization': `Token ${DEEPGRAM_API_KEY}`,
            'Content-Type': contentType
          },
          body: buffer
        }
      );
      if (!response.ok) {
        const err = await response.text();
        throw new Error(`Deepgram API error: ${err}`);
      }
      const data = await response.json();
      const transcript = data?.results?.channels?.[0]?.alternatives?.[0]?.transcript || '';
      return res.json({ transcript, provider: 'deepgram' });
    }

    // ── Option B: Groq / OpenAI Whisper ──
    const useGroq = !!GROQ_API_KEY;
    const apiKey = useGroq ? GROQ_API_KEY : OPENAI_API_KEY;
    const apiUrl = useGroq
      ? 'https://api.groq.com/openai/v1/audio/transcriptions'
      : 'https://api.openai.com/v1/audio/transcriptions';
    const model = useGroq ? 'whisper-large-v3-turbo' : 'whisper-1';

    const ext = contentType.includes('mp4') ? 'mp4' : 'webm';
    const blob = new Blob([buffer], { type: contentType });
    const formData = new FormData();
    formData.append('file', blob, `recording.${ext}`);
    formData.append('model', model);
    formData.append('language', 'en');

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}` },
      body: formData
    });
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Transcription API error: ${err}`);
    }
    const data = await response.json();
    res.json({ transcript: data.text || '', provider: useGroq ? 'groq' : 'openai' });
  } catch(e) {
    console.error('Transcribe error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── CLAUDE EVALUATION PROXY ──────────────────────────────────────────────────
app.post('/api/eval', authMiddleware, async (req, res) => {
  const { target, transcripts } = req.body;
  if (!target || !transcripts) return res.status(400).json({ error: 'Missing target or transcripts' });

  const spokenStr = (transcripts || []).slice(0, 5).join(' | ');
  const prompt = `You are a pronunciation accuracy judge for an English speech karaoke game.
Target sentence: "${target}"
Player's speech recognition alternatives: "${spokenStr}"

Rules:
- Score 0.0 to 1.0 based on how closely ANY alternative matches the target.
- Be lenient with minor differences: dropped articles, small word substitutions, singular/plural.
- Be stricter on key content words.
- "passed" = true if score >= 0.65
- "feedback": short and encouraging, max 8 words.
- "wrongWords": array of target words the player clearly mispronounced or missed (lowercase, max 5).

Reply ONLY with valid JSON, no markdown fences:
{"score":0.85,"passed":true,"feedback":"Great pronunciation!","wrongWords":[]}`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 200,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!response.ok) throw new Error(`Anthropic API error: ${response.status}`);
    const data = await response.json();
    const text = data.content[0].text.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();
    res.json(JSON.parse(text));
  } catch (e) {
    console.error('Eval error:', e.message);
    res.status(500).json({ error: 'Evaluation failed', fallback: true });
  }
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🎤 Speech Karaoke Server running at http://localhost:${PORT}`);
  console.log(`   Admin panel: http://localhost:${PORT}/admin.html`);
  console.log(`   Student app: http://localhost:${PORT}/\n`);
});

// ─── SENTENCE BANK (500 sentences × 5 levels, 5 per day × 20 days) ───────────
const SENTENCE_BANK = {
  1: [
    'Hello, how are you today?',
    'Good morning, nice to meet you.',
    'Thank you very much for your help.',
    'My name is Sarah, and I am a student.',
    'Have a wonderful day!',
    'What is your name?',
    'I am fine, thank you.',
    'Where are you from?',
    'Nice to meet you too.',
    'How old are you?',
    'I live in the city.',
    'She is my best friend.',
    'He likes to play football.',
    'We go to school every day.',
    'I am very happy today.',
    'Please sit down.',
    'Can you help me?',
    'Yes, of course!',
    'No, thank you.',
    "I don't understand.",
    'Please speak slowly.',
    'What time is it?',
    "It is three o'clock.",
    'Good afternoon!',
    'Good evening!',
    'Good night, sleep well.',
    'See you tomorrow.',
    'Take care of yourself.',
    'I am hungry.',
    'I am thirsty.',
    'I like apples and oranges.',
    'She has a red bag.',
    'He is my brother.',
    'They are my parents.',
    'This is my house.',
    'That is a big dog.',
    'The cat is sleeping.',
    'I drink water every morning.',
    'We eat lunch at noon.',
    'She reads books every night.',
    'He walks to school.',
    'I love my family.',
    'The sky is blue today.',
    'It is hot outside.',
    'I feel tired today.',
    'Please open the door.',
    'Close the window, please.',
    'Turn on the light.',
    'I have two brothers.',
    'She has one sister.',
    'My mother is a teacher.',
    'His father is a doctor.',
    'We play games together.',
    'I wake up at seven.',
    'She goes to bed early.',
    'The food smells delicious.',
    'This is very tasty.',
    'I need some water.',
    'Can I borrow your pen?',
    'Here you go.',
    'You are very kind.',
    'I am so sorry.',
    'That is okay.',
    "Don't worry about it.",
    'I am from Japan.',
    'She speaks English well.',
    'He is a good student.',
    'We are good friends.',
    'I study English every day.',
    'She loves to sing songs.',
    'He plays the guitar.',
    'We watch TV together.',
    'I go shopping on Saturdays.',
    'She cooks very well.',
    'He drinks coffee in the morning.',
    'I brush my teeth twice a day.',
    'She combs her hair.',
    'He wears glasses.',
    'I have a pet cat.',
    'She rides a bicycle.',
    'He drives a blue car.',
    'We live near the park.',
    'I like sunny weather.',
    'She prefers cold weather.',
    'He enjoys swimming.',
    'I read the newspaper.',
    'She writes in her diary.',
    'He paints beautiful pictures.',
    'We sing in the choir.',
    'I play chess with my dad.',
    'She dances in her room.',
    'He runs every morning.',
    'I have a big smile.',
    'She has a kind heart.',
    'He is always on time.',
    'We help each other.',
    'I say please and thank you.',
    'She greets everyone nicely.',
    'He shares his food.',
    'We are a happy family.',
  ],
  2: [
    'Could you please tell me where the library is?',
    'I would like to order a cup of coffee, please.',
    'What time does the next train leave the station?',
    'Excuse me, how much does this item cost?',
    'The weather today is absolutely beautiful.',
    'Can you recommend a good restaurant nearby?',
    'I need to catch the bus to downtown.',
    'Do you have this shirt in a larger size?',
    'How long does it take to get there?',
    'Could I have the menu, please?',
    'I would like to make a reservation for two.',
    'Is there a pharmacy close to here?',
    'What are the opening hours of the museum?',
    'I am looking for the nearest ATM machine.',
    'Can you please write that down for me?',
    'I would like to pay by credit card.',
    'Do you accept cash payments here?',
    'Could you give me a receipt, please?',
    'The traffic was very heavy this morning.',
    'I missed the last bus and need a taxi.',
    'Can you call me a cab, please?',
    'How much is a one-way ticket to the airport?',
    'Is this seat taken?',
    'May I sit here, please?',
    'I am waiting for a friend.',
    'Could you take a photo of us, please?',
    'Where is the nearest restroom?',
    'I would like to exchange some money.',
    'What is the exchange rate today?',
    'Can you speak a little more slowly?',
    "I am sorry, I didn't catch that.",
    'Could you repeat that, please?',
    'I am a bit lost and need some help.',
    'Do you have a map of the city?',
    'How do I get to the city center from here?',
    'Is the post office far from here?',
    'I need to send this package urgently.',
    'What time does the supermarket close?',
    'Do you have any vegetarian options?',
    'I am allergic to nuts and shellfish.',
    'Could I have some more water, please?',
    'The bill seems incorrect.',
    'I think there is a mistake on the receipt.',
    'Could we have separate checks, please?',
    'I would like to return this item.',
    'It does not fit me properly.',
    'Do you offer a refund or exchange?',
    'I booked a room under the name Johnson.',
    'What time is check-in and check-out?',
    'Is breakfast included in the price?',
    'Could I have an extra pillow, please?',
    'The air conditioning in my room is not working.',
    'Can someone fix the problem as soon as possible?',
    'I need a wake-up call at six in the morning.',
    'Is there a gym or swimming pool in the hotel?',
    'Where is the nearest bus stop from here?',
    'Does this train stop at Central Station?',
    'I need to change my flight reservation.',
    'My luggage has not arrived yet.',
    'Can you help me find my suitcase?',
    'I would like a window seat, please.',
    'Is the flight on time today?',
    'What gate do I go to for boarding?',
    'I have a connecting flight in two hours.',
    'My passport is in my carry-on bag.',
    'Do I need to fill in a customs form?',
    'I am here on a business trip.',
    'How long is your visa valid for?',
    'Is there free Wi-Fi available here?',
    'What is the password for the internet?',
    'My phone battery is running low.',
    'Could I borrow your charger for a moment?',
    'I need to make an important phone call.',
    'Can you recommend something to do in the evening?',
    'What are the must-see attractions in this city?',
    'Is this area safe to walk around at night?',
    'I would love to try the local cuisine.',
    'What is the most popular dish here?',
    'Could you make it less spicy, please?',
    'I would like my steak well done.',
    'Can I have the dessert menu too?',
    'This meal is absolutely wonderful.',
    'Compliments to the chef!',
    'I will definitely come back here again.',
    'Could you wrap the leftovers to go?',
    'Where can I buy souvenirs around here?',
    'Do you have a loyalty card or discount?',
    'I am just browsing, thank you.',
    'Does this come with a warranty?',
    'Can I try this on before buying?',
    'Is there a sale or special offer today?',
    'Do you ship internationally?',
    'I would like to speak to the manager.',
    'The service here has been excellent.',
    'I had a wonderful experience today.',
    'I will recommend this place to my friends.',
    'Could you please validate my parking ticket?',
    'Where do I catch the shuttle to the terminal?',
    'Thank you for all your help today.',
    'Thank you for all your help today.',
  ],
  3: [
    'The quick brown fox jumps over the lazy dog.',
    'Every cloud has a silver lining if you look for it.',
    'Actions speak louder than words in every situation.',
    'Knowledge is power when applied with wisdom.',
    'She sells seashells by the seashore every morning.',
    'The early bird catches the worm, so wake up on time.',
    'You can lead a horse to water, but you cannot make it drink.',
    'A penny saved is a penny earned at the end of the day.',
    "Don't judge a book by its cover, because looks can be deceiving.",
    'Time flies when you are having fun with good friends.',
    'Better late than never, but better never late is even wiser.',
    'Two heads are better than one when solving difficult problems.',
    'The grass is always greener on the other side of the fence.',
    'Where there is a will, there is always a way forward.',
    'All that glitters is not gold, so be careful what you choose.',
    'A rolling stone gathers no moss over time.',
    'Birds of a feather flock together in every season.',
    'Out of sight, out of mind is often very true.',
    'Every rose has its thorn, no matter how beautiful it looks.',
    'Practice makes perfect, so never stop improving yourself.',
    'Laughter is the best medicine for a troubled heart.',
    'Honesty is the best policy in all areas of life.',
    'Curiosity killed the cat, but satisfaction brought it back.',
    "The more you know, the more you realize you don't know.",
    'Life is a journey, not a destination you rush to reach.',
    'You miss a hundred percent of the shots you never take.',
    'It always seems impossible until someone actually does it.',
    'The only way to do great work is to love what you do.',
    'In the middle of every difficulty lies a great opportunity.',
    'Success is not final, and failure is not fatal in the long run.',
    'She was walking slowly through the colorful autumn leaves.',
    'He decided to take a different path and discovered something wonderful.',
    'They stayed up all night finishing the exciting science project.',
    'We sat by the river and watched the sun slowly set.',
    'I learned something important about myself on that long journey.',
    'The children laughed and played happily in the afternoon sunshine.',
    'She opened the letter carefully and read every single word.',
    'He prepared a delicious meal for everyone without any help.',
    'We explored the ancient ruins on a warm and clear summer day.',
    'I finally finished the book after months of reading it slowly.',
    'The scientist made an extraordinary discovery that changed everything.',
    'She painted a magnificent landscape that left everyone speechless.',
    'He delivered an inspiring speech that moved the entire audience.',
    'They built a small wooden cabin deep in the forest together.',
    'We climbed the steep mountain and enjoyed the breathtaking view.',
    'The chef prepared each dish with incredible care and precision.',
    'She taught herself three languages through dedication and hard work.',
    'He ran the entire marathon without stopping to rest once.',
    'They traveled across the country with nothing but a backpack.',
    'We created a wonderful garden filled with flowers of every color.',
    'The thunder roared loudly as the heavy rain began to fall.',
    'She looked out the window and felt a sudden sense of peace.',
    'He opened the old box and found letters from decades ago.',
    'They danced all evening to the live music at the festival.',
    'We stayed silent and listened carefully to the beautiful birdsong.',
    'The river flowed gently through the quiet and peaceful valley.',
    'She smiled warmly at the stranger and offered to help them.',
    'He worked tirelessly for years to achieve his lifelong dream.',
    'They gathered around the fireplace and shared stories all night.',
    'We planted seeds in the spring and watched them bloom in summer.',
    'The little girl sang a lullaby softly to her sleeping doll.',
    'He fixed the old bicycle and gave it a fresh coat of paint.',
    'She wrote a long letter to her grandmother overseas.',
    'They rescued the injured bird and nursed it back to health.',
    'We organized a surprise party that nobody expected at all.',
    'The teacher asked the students to think creatively and freely.',
    'She solved the difficult puzzle in less than ten minutes.',
    'He greeted every person he met with a genuine warm smile.',
    'They launched a small business with very little money at first.',
    'We stayed calm under pressure and found the right solution.',
    'The scientist explained the theory in the simplest way possible.',
    'She adapted quickly to the changes and made the best of them.',
    'He forgave the mistake and chose to move forward with kindness.',
    'They watched the night sky and counted every visible star.',
    'We listened to the old records and remembered happier times.',
    'The students cheered loudly when they heard the good news.',
    'She returned home after a long trip feeling refreshed and grateful.',
    'He drew a detailed map of the entire neighborhood from memory.',
    'They baked fresh bread every morning for the whole community.',
    'We celebrated the achievement with a long and cheerful dinner.',
    'The artist painted for hours without noticing the time passing.',
    'She shared her story and inspired everyone who heard it.',
    'He remembered every detail of that unforgettable summer afternoon.',
    'They donated their time and energy to help the local shelter.',
    'We made a promise and kept it no matter how hard it was.',
    'The old bridge stood strong despite years of wind and rain.',
    'She hummed a familiar tune while watering her garden plants.',
    'He listened patiently while his friend talked about his worries.',
    'They paddled across the calm lake as the morning fog lifted.',
    'We cooked an enormous feast and invited everyone we knew.',
    'The mountain trail was steep but the view was worth every step.',
    'She wrapped the gift carefully and wrote a heartfelt message inside.',
    'He stayed positive even when things were not going his way.',
    'They cleaned the entire park and left it better than before.',
    'We learned that kindness and patience are never wasted on anyone.',
    'The sunset painted the sky in shades of orange, red, and gold.',
    'She believed in herself when no one else seemed to care.',
    'He stood at the crossroads and made the most important decision.',
    'They crossed the finish line together, hand in hand, smiling.',
    'Technology continues to transform how we communicate globally.',
  ],
  4: [
    'The professor explained the complex theory with remarkable clarity.',
    'Environmental conservation requires collective effort and dedication.',
    'Critical thinking is an essential skill for academic success.',
    'International collaboration drives innovation across all industries.',
    'The report highlighted several key challenges facing the organization.',
    'Data analysis plays a crucial role in modern decision-making processes.',
    'Effective leadership requires empathy, vision, and strong communication skills.',
    'The research findings suggest a significant correlation between the variables.',
    'Developing countries face unique economic and social development challenges.',
    'The curriculum was redesigned to better meet the needs of diverse learners.',
    'Strategic planning enables organizations to anticipate and respond to change.',
    'The committee reviewed the proposal and requested additional supporting evidence.',
    'Renewable energy sources offer a sustainable alternative to fossil fuels.',
    'Public health initiatives require strong government and community partnerships.',
    'The study examined the long-term effects of early childhood education programs.',
    'Ethical considerations must guide the development and application of technology.',
    'Intercultural competence is increasingly valued in today\'s global workforce.',
    'The board of directors approved the revised budget for the next fiscal year.',
    'Academic integrity is fundamental to the credibility of scholarly research.',
    'The symposium brought together experts from a wide range of disciplines.',
    'Institutional support is vital for fostering a culture of continuous learning.',
    'The implementation of new policies requires careful planning and coordination.',
    'A comprehensive review of existing literature was conducted prior to the study.',
    'The project demonstrated that community engagement leads to better outcomes.',
    'Advances in medical research have significantly improved patient care standards.',
    'Effective negotiation skills are essential in both business and diplomacy.',
    'The findings were consistent with previous studies conducted on the same subject.',
    'Urban planning must balance growth with the preservation of green spaces.',
    'The analysis revealed patterns that were not immediately apparent in the raw data.',
    'Corporate social responsibility has become a priority for major organizations.',
    'The conference will address emerging trends in artificial intelligence and ethics.',
    'Significant investment in infrastructure is required to support economic growth.',
    'The feedback from stakeholders was incorporated into the final version of the plan.',
    'Professional development opportunities enhance employee performance and retention.',
    'The legal framework governing data privacy has evolved considerably in recent years.',
    'Peer collaboration encourages knowledge sharing and mutual academic growth.',
    'The authors argue convincingly that traditional approaches require reconsideration.',
    'Budgetary constraints have limited the scope of the proposed research project.',
    'The panel discussion generated valuable insights from participants across sectors.',
    'Transparent communication fosters trust within any organization or institution.',
    'The methodology section clearly outlined the procedures used in data collection.',
    'Cross-sector partnerships are essential for addressing complex societal challenges.',
    'The pilot program was evaluated using both quantitative and qualitative measures.',
    'A diverse workforce brings different perspectives and strengthens problem-solving.',
    'The university offers interdisciplinary programs that bridge multiple academic fields.',
    'Workforce automation presents both opportunities and significant challenges for employees.',
    'The allocation of resources must be guided by clearly defined strategic priorities.',
    'Mentorship programs have proven effective in supporting professional advancement.',
    'The hypothesis was tested through a series of carefully controlled experiments.',
    'Globalization has increased economic interdependence among nations significantly.',
    'The executive team presented the quarterly results to shareholders last Friday.',
    'Climate adaptation strategies must be tailored to local and regional conditions.',
    'Rigorous assessment criteria ensure consistency and fairness in academic evaluation.',
    'The policy brief outlined a series of evidence-based recommendations for reform.',
    'Organizational culture has a profound influence on employee motivation and output.',
    'The seminar offered participants an opportunity to engage with current scholarship.',
    'Technological literacy is increasingly considered a core competency in education.',
    'The audit uncovered discrepancies that required immediate corrective action.',
    'Stakeholder engagement is a critical component of successful project management.',
    'The grant application was submitted after extensive consultation with all partners.',
    'Supply chain resilience has become a top priority following recent global disruptions.',
    'The professor emphasized the importance of citing sources accurately in all work.',
    'Diversity and inclusion initiatives contribute to a more equitable workplace.',
    'The national curriculum was updated to reflect current advances in science and technology.',
    'Social mobility is influenced by access to quality education and career opportunities.',
    'The research team published their findings in a peer-reviewed international journal.',
    'Risk assessment frameworks help organizations prepare for unforeseen circumstances.',
    'The presentation was well-structured and supported by compelling empirical data.',
    'Mental health awareness in the workplace has gained considerable attention recently.',
    'The contract stipulates specific obligations and timelines for each party involved.',
    'Innovation ecosystems thrive when government, industry, and academia collaborate closely.',
    'The literature review identified significant gaps in the existing body of knowledge.',
    'Measurable outcomes are essential for evaluating the effectiveness of any program.',
    'The partnership agreement was finalized after several rounds of careful negotiation.',
    'Student-centered approaches to learning improve engagement and academic performance.',
    'The annual report detailed the organization\'s achievements over the past twelve months.',
    'Public discourse on climate change must move from awareness to concrete action.',
    'The task force recommended establishing a monitoring committee to track progress.',
    'Constructive feedback delivered respectfully accelerates individual professional growth.',
    'The investigation was conducted independently to ensure transparency and credibility.',
    'Cross-cultural communication skills are increasingly important in global business.',
    'The model predicts outcomes based on historical data and current market trends.',
    'Sustainable business practices reduce environmental impact while maintaining profitability.',
    'The workshop provided practical tools for improving academic writing and structure.',
    'Media literacy empowers individuals to critically evaluate information from multiple sources.',
    'The delegation attended the summit to discuss trade agreements and bilateral relations.',
    'Continued investment in research and development drives long-term economic competitiveness.',
    'The evaluation framework incorporated feedback from students, staff, and administrators.',
    'Digital transformation requires organizations to rethink existing processes and structures.',
    'The consensus among experts is that early intervention produces the best outcomes.',
    'Financial transparency builds confidence among investors and other key stakeholders.',
    'The policy aims to reduce inequality and improve access to essential public services.',
    'Collaborative research networks accelerate discovery and broaden scholarly impact.',
    'The committee will reconvene next month to review progress against the agreed targets.',
    'Adaptive leadership enables organizations to navigate uncertainty with greater confidence.',
    'The strategic framework aligned institutional goals with broader national priorities.',
    'A culture of accountability promotes integrity and continuous improvement across all levels.',
    'The unprecedented technological revolution has fundamentally altered civilization.',
    'Sophisticated algorithms analyze enormous quantities of unstructured data.',
    'Philosophical perspectives significantly influence contemporary educational methodologies.',
  ],
  5: [
    'Sustainable development necessitates balancing economic growth with environmental preservation.',
    'Interdisciplinary research fosters comprehensive solutions to multifaceted challenges.',
    'How much wood would a woodchuck chuck if a woodchuck could chuck wood?',
    'Peter Piper picked a peck of pickled peppers from the pepper patch.',
    'She sells seashells by the seashore, and the shells she sells are surely seashells.',
    'Red lorry, yellow lorry, red lorry, yellow lorry, red lorry, yellow lorry.',
    "Whether the weather is cold, or whether the weather is hot, we'll weather the weather whatever the weather.",
    'The six sick sheep stood still on the slippery slope in the silent snow.',
    'Freshly fried flying fish, freshly fried flesh, freshly fried flying fish.',
    'I scream, you scream, we all scream for ice cream on a hot summer afternoon.',
    'Lesser leather never weathered wetter weather better than this particular leather.',
    'A big black bug bit a big black bear, making the big black bear bleed blood.',
    'Unique New York, unique New York, you know you need unique New York.',
    'If two witches were watching two watches, which witch would watch which watch?',
    'I thought I thought of thinking of thanking you, but then I thought again.',
    "Fuzzy Wuzzy was a bear, Fuzzy Wuzzy had no hair, Fuzzy Wuzzy wasn't fuzzy, was he?",
    'The thirty-three thieves thought that they thrilled the throne throughout Thursday.',
    'To be, or not to be, that is the question: whether it is nobler in the mind to suffer.',
    'It was the best of times, it was the worst of times, it was the age of wisdom.',
    'Two roads diverged in a wood, and I took the one less traveled by.',
    'All animals are equal, but some animals are more equal than others.',
    'It does not matter how slowly you go, as long as you do not stop moving forward.',
    'In three words I can sum up everything I have learned about life: it goes on.',
    'You have brains in your head and feet in your shoes, you can steer yourself any direction you choose.',
    'The secret of getting ahead is getting started, however small the first step may be.',
    'Not everything that is faced can be changed, but nothing can be changed until it is faced.',
    'The measure of intelligence is the ability to change with changing circumstances.',
    'Quantum mechanics revolutionized our comprehension of subatomic particle behavior.',
    'The proliferation of misinformation undermines democratic institutions and public discourse.',
    "Neuroplasticity demonstrates the brain's remarkable capacity for lifelong adaptation.",
    'Geopolitical realignments are reshaping international trade and diplomatic relationships.',
    'The epistemological implications of artificial intelligence challenge longstanding philosophical assumptions.',
    'Sociological paradigms continuously evolve to reflect shifting cultural and demographic realities.',
    'The juxtaposition of tradition and modernity creates fascinating cultural contradictions.',
    'Bureaucratic inefficiency often impedes the implementation of well-intentioned social policies.',
    'Astronomical observations have fundamentally transformed our understanding of the cosmos.',
    'The constitutional framework delineates the boundaries of governmental authority and civic rights.',
    'Bioethical considerations increasingly shape the parameters of contemporary medical research.',
    'The metaphysical dimensions of consciousness remain profoundly elusive to scientific inquiry.',
    'Extraordinary perseverance and meticulous attention to detail distinguish exceptional scholars.',
    'The rhetorical sophistication of the diplomat defused an extraordinarily volatile situation.',
    'Phenomenological approaches offer nuanced insights into lived human experience.',
    'Technological determinism oversimplifies the extraordinarily complex relationship between society and innovation.',
    'The ramifications of deforestation extend far beyond the immediately visible environmental damage.',
    'Counterintuitive findings frequently generate the most significant scientific breakthroughs.',
    'Psycholinguistic research illuminates the intricate processes underlying language acquisition.',
    'The dialectical relationship between theory and practice drives intellectual and practical progress.',
    'She articulated her extraordinarily complex argument with breathtaking eloquence and precision.',
    'The irrefutable evidence compelled even the most skeptical observers to reconsider their positions.',
    'Philosophical skepticism encourages rigorous examination of assumptions we take for granted.',
    'The intrinsically ambiguous nature of language creates perpetual challenges for translators.',
    'Paradigm shifts in scientific understanding often encounter substantial institutional resistance.',
    'The labyrinthine complexities of international law defy straightforward interpretation.',
    'Anthropological fieldwork requires extraordinary cultural sensitivity and methodological rigor.',
    'The subliminal influence of media narratives shapes collective perceptions in profound ways.',
    'Existential questions about purpose and meaning permeate great works of world literature.',
    'The symbiotic relationship between innovation and regulation requires continuous renegotiation.',
    'She navigated the extraordinarily turbulent waters of political transition with remarkable composure.',
    'The ramifications of climate change will reverberate across generations yet unborn.',
    'Hermeneutical approaches seek to uncover layers of meaning embedded within complex texts.',
    'The unprecedented convergence of digital technologies is redefining the boundaries of human creativity.',
    'Disproportionate economic inequality perpetuates cycles of deprivation and social immobility.',
    'The proliferation of surveillance technologies raises profound questions about privacy and autonomy.',
    'Cognitive dissonance arises when individuals encounter information that contradicts their existing beliefs.',
    'The philosophical tradition of empiricism insists that knowledge derives primarily from sensory experience.',
    'Macroeconomic fluctuations disproportionately impact the most economically vulnerable populations.',
    'Transcultural competence is indispensable for effective leadership in pluralistic societies.',
    'The extraordinarily intricate web of ecological relationships sustains biodiversity on our planet.',
    'Postcolonial scholarship challenges Eurocentric narratives embedded within academic disciplines.',
    'The inexorable advancement of automation necessitates profound rethinking of workforce preparation.',
    'Epistemological humility acknowledges the inherent limitations of human knowledge and perception.',
    'The staggering complexity of the human genome continues to astonish molecular biologists worldwide.',
    'Deconstructionist criticism interrogates the assumptions and contradictions within canonical literary texts.',
    'The trajectory of democratic governance is determined by the active engagement of informed citizens.',
    'Neuroscientific advances are challenging long-held assumptions about consciousness and subjective experience.',
    'The inextricable entanglement of economics and politics complicates straightforward policy prescriptions.',
    'Catastrophic biodiversity loss threatens the resilience of ecosystems upon which humanity depends.',
    'Philosophical ethics grapples with the extraordinarily difficult questions of justice, duty, and virtue.',
    'The transformative potential of education is greatest when it cultivates curiosity and independent thought.',
    'Societal expectations unconsciously constrain individual identity formation in profound and lasting ways.',
    'The herculean challenge of eradicating systemic inequality demands sustained collective commitment.',
    "Technological acceleration outpaces humanity's collective capacity to contemplate its ethical implications.",
    'The labyrinthine intricacies of financial derivatives contributed significantly to catastrophic economic collapse.',
    'Anthropogenic climate disruption represents the defining civilizational challenge of the twenty-first century.',
    'The multidimensional nature of poverty requires holistic, integrated, and community-centered responses.',
    'Interdependence among nations necessitates multilateral frameworks for addressing transboundary challenges.',
    'The extraordinary fragility of peace underscores the imperative of sustained diplomatic engagement.',
    'Revolutionary artistic movements inevitably reflect the deepest anxieties and aspirations of their era.',
    'The persistent question of free will versus determinism has occupied philosophers across millennia.',
    'Extraordinary intellectual humility is the hallmark of the truly great scientist and scholar.',
    'The irreversible consequences of certain decisions demand that we proceed with profound deliberation.',
    'Transformational leadership inspires individuals to transcend self-interest in service of a greater purpose.',
    'The bewildering complexity of modern existence demands both analytical precision and philosophical depth.',
    'Nothing in life is to be feared, it is only to be understood, and that is our greatest challenge.',
    'Nothing in life is to be feared, it is only to be understood, and that is our greatest challenge.',
    'Nothing in life is to be feared, it is only to be understood, and that is our greatest challenge.',
    'Nothing in life is to be feared, it is only to be understood, and that is our greatest challenge.',
    'Nothing in life is to be feared, it is only to be understood, and that is our greatest challenge.',
    'Nothing in life is to be feared, it is only to be understood, and that is our greatest challenge.',
    'Nothing in life is to be feared, it is only to be understood, and that is our greatest challenge.',
  ]
};
