const express = require('express');
const path = require('path');
const crypto = require('crypto');
const initSqlJs = require('sql.js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let db;

// Helper function for parameterized SELECT queries in sql.js
function dbQuery(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        if (params.length > 0) {
            stmt.bind(params);
        }
        const results = [];
        while (stmt.step()) {
            results.push(stmt.getAsObject());
        }
        stmt.free();
        return results;
    } catch (err) {
        console.error('DB Query Error:', err, sql, params);
        return [];
    }
}

// Helper function for parameterized INSERT/UPDATE/DELETE
function dbRun(sql, params = []) {
    try {
        db.run(sql, params);
        return true;
    } catch (err) {
        console.error('DB Run Error:', err, sql, params);
        return false;
    }
}

// Simple password hashing
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(':');
    const verifyHash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash === verifyHash;
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Initialize database
async function initDatabase() {
    const SQL = await initSqlJs();
    db = new SQL.Database();
    
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            display_name TEXT,
            profile_image TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS adventurers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            image TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            dates TEXT NOT NULL,
            start_hour INTEGER NOT NULL,
            end_hour INTEGER NOT NULL,
            creator_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (creator_id) REFERENCES users(id)
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS availability (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            participant_name TEXT NOT NULL,
            participant_image TEXT,
            user_id INTEGER,
            slots TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
    
    console.log('Database initialized');
}

// Auth middleware
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    
    if (!token) {
        req.user = null;
        return next();
    }
    
    const results = dbQuery(`
        SELECT s.user_id, u.username, u.display_name, u.profile_image 
        FROM sessions s 
        JOIN users u ON s.user_id = u.id 
        WHERE s.token = ?
    `, [token]);
    
    if (results.length > 0) {
        const row = results[0];
        req.user = { 
            id: row.user_id, 
            username: row.username, 
            displayName: row.display_name, 
            profileImage: row.profile_image 
        };
    } else {
        req.user = null;
    }
    next();
}

function requireAuth(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
}

// ============ AUTH ROUTES ============

app.post('/api/auth/register', (req, res) => {
    const { username, password, displayName } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    
    if (username.length < 3) {
        return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }
    
    if (password.length < 4) {
        return res.status(400).json({ error: 'Password must be at least 4 characters' });
    }
    
    const existing = dbQuery(`SELECT id FROM users WHERE username = ?`, [username.toLowerCase()]);
    if (existing.length > 0) {
        return res.status(400).json({ error: 'Username already taken' });
    }
    
    const hashedPassword = hashPassword(password);
    const name = displayName || username;
    
    dbRun(`INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)`, 
        [username.toLowerCase(), hashedPassword, name]);
    
    const userResult = dbQuery(`SELECT last_insert_rowid() as id`);
    const userId = userResult[0].id;
    const token = generateToken();
    
    dbRun(`INSERT INTO sessions (user_id, token) VALUES (?, ?)`, [userId, token]);
    
    res.json({
        token,
        user: {
            id: userId,
            username: username.toLowerCase(),
            displayName: name,
            profileImage: null
        }
    });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    
    const results = dbQuery(`SELECT id, username, password, display_name, profile_image FROM users WHERE username = ?`, 
        [username.toLowerCase()]);
    
    if (results.length === 0) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const user = results[0];
    
    if (!verifyPassword(password, user.password)) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const token = generateToken();
    dbRun(`INSERT INTO sessions (user_id, token) VALUES (?, ?)`, [user.id, token]);
    
    res.json({
        token,
        user: {
            id: user.id,
            username: user.username,
            displayName: user.display_name,
            profileImage: user.profile_image
        }
    });
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (token) {
        dbRun(`DELETE FROM sessions WHERE token = ?`, [token]);
    }
    res.json({ success: true });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    if (!req.user) {
        return res.json({ user: null });
    }
    res.json({ user: req.user });
});

// ============ PROFILE ROUTES ============

app.put('/api/profile', authenticateToken, requireAuth, (req, res) => {
    const { displayName, profileImage } = req.body;
    
    dbRun(`UPDATE users SET display_name = ?, profile_image = ? WHERE id = ?`,
        [displayName || req.user.displayName, profileImage || null, req.user.id]);
    
    res.json({ success: true });
});

app.put('/api/profile/password', authenticateToken, requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new password required' });
    }
    
    if (newPassword.length < 4) {
        return res.status(400).json({ error: 'New password must be at least 4 characters' });
    }
    
    const results = dbQuery(`SELECT password FROM users WHERE id = ?`, [req.user.id]);
    if (results.length === 0) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    if (!verifyPassword(currentPassword, results[0].password)) {
        return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    const hashedNew = hashPassword(newPassword);
    dbRun(`UPDATE users SET password = ? WHERE id = ?`, [hashedNew, req.user.id]);
    
    res.json({ success: true });
});

app.get('/api/profile/events', authenticateToken, requireAuth, (req, res) => {
    const created = dbQuery(`
        SELECT id, name, description, dates, created_at 
        FROM events WHERE creator_id = ?
        ORDER BY created_at DESC
    `, [req.user.id]);
    
    const participated = dbQuery(`
        SELECT DISTINCT e.id, e.name, e.description, e.dates, e.created_at
        FROM events e
        JOIN availability a ON e.id = a.event_id
        WHERE a.user_id = ? AND (e.creator_id IS NULL OR e.creator_id != ?)
        ORDER BY e.created_at DESC
    `, [req.user.id, req.user.id]);
    
    const formatEvents = (rows) => rows.map(row => ({
        id: row.id,
        name: row.name,
        description: row.description,
        dates: JSON.parse(row.dates),
        createdAt: row.created_at
    }));
    
    res.json({
        created: formatEvents(created),
        participated: formatEvents(participated)
    });
});

// ============ ADVENTURER ROUTES ============

app.get('/api/adventurers', authenticateToken, requireAuth, (req, res) => {
    const results = dbQuery(`
        SELECT id, name, image, created_at 
        FROM adventurers WHERE user_id = ?
        ORDER BY created_at DESC
    `, [req.user.id]);
    
    const adventurers = results.map(row => ({
        id: row.id,
        name: row.name,
        image: row.image,
        createdAt: row.created_at
    }));
    
    res.json(adventurers);
});

app.post('/api/adventurers', authenticateToken, requireAuth, (req, res) => {
    const { name, image } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Name required' });
    }
    
    dbRun(`INSERT INTO adventurers (user_id, name, image) VALUES (?, ?, ?)`,
        [req.user.id, name, image || null]);
    
    const result = dbQuery(`SELECT last_insert_rowid() as id`);
    const id = result[0].id;
    
    res.json({ id, name, image });
});

app.put('/api/adventurers/:id', authenticateToken, requireAuth, (req, res) => {
    const { name, image } = req.body;
    const { id } = req.params;
    
    const check = dbQuery(`SELECT id FROM adventurers WHERE id = ? AND user_id = ?`, [id, req.user.id]);
    if (check.length === 0) {
        return res.status(404).json({ error: 'Adventurer not found' });
    }
    
    dbRun(`UPDATE adventurers SET name = ?, image = ? WHERE id = ?`,
        [name, image || null, id]);
    
    res.json({ success: true });
});

app.delete('/api/adventurers/:id', authenticateToken, requireAuth, (req, res) => {
    const { id } = req.params;
    
    const check = dbQuery(`SELECT id FROM adventurers WHERE id = ? AND user_id = ?`, [id, req.user.id]);
    if (check.length === 0) {
        return res.status(404).json({ error: 'Adventurer not found' });
    }
    
    dbRun(`DELETE FROM adventurers WHERE id = ?`, [id]);
    
    res.json({ success: true });
});

// ============ EVENT ROUTES ============

app.post('/api/events', authenticateToken, (req, res) => {
    const { name, description, dates, startHour, endHour } = req.body;
    
    if (!name || !dates || dates.length === 0) {
        return res.status(400).json({ error: 'Name and dates are required' });
    }
    
    const eventId = crypto.randomBytes(4).toString('hex');
    const creatorId = req.user ? req.user.id : null;
    
    dbRun(`
        INSERT INTO events (id, name, description, dates, start_hour, end_hour, creator_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [eventId, name, description || '', JSON.stringify(dates), startHour || 9, endHour || 22, creatorId]);
    
    res.json({ 
        id: eventId, 
        url: `/event/${eventId}` 
    });
});

app.get('/api/events/:id', (req, res) => {
    const { id } = req.params;
    
    const eventResults = dbQuery(`
        SELECT id, name, description, dates, start_hour, end_hour, creator_id, created_at
        FROM events WHERE id = ?
    `, [id]);
    
    if (eventResults.length === 0) {
        return res.status(404).json({ error: 'Event not found' });
    }
    
    const event = eventResults[0];
    
    const availResults = dbQuery(`
        SELECT participant_name, participant_image, user_id, slots
        FROM availability WHERE event_id = ?
    `, [id]);
    
    const participants = [];
    const availability = {};
    const participantImages = {};
    
    availResults.forEach(row => {
        participants.push(row.participant_name);
        availability[row.participant_name] = JSON.parse(row.slots);
        if (row.participant_image) {
            participantImages[row.participant_name] = row.participant_image;
        }
    });
    
    res.json({
        id: event.id,
        name: event.name,
        description: event.description,
        dates: JSON.parse(event.dates),
        startHour: event.start_hour,
        endHour: event.end_hour,
        creatorId: event.creator_id,
        createdAt: event.created_at,
        participants,
        participantImages,
        availability
    });
});

app.post('/api/events/:id/availability', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { participantName, participantImage, slots } = req.body;
    
    if (!participantName) {
        return res.status(400).json({ error: 'Participant name required' });
    }
    
    const eventCheck = dbQuery(`SELECT id FROM events WHERE id = ?`, [id]);
    if (eventCheck.length === 0) {
        return res.status(404).json({ error: 'Event not found' });
    }
    
    const userId = req.user ? req.user.id : null;
    
    const existing = dbQuery(`SELECT id FROM availability WHERE event_id = ? AND participant_name = ?`, [id, participantName]);
    
    if (existing.length > 0) {
        dbRun(`
            UPDATE availability 
            SET slots = ?, participant_image = ?, user_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE event_id = ? AND participant_name = ?
        `, [JSON.stringify(slots), participantImage || null, userId, id, participantName]);
    } else {
        dbRun(`
            INSERT INTO availability (event_id, participant_name, participant_image, user_id, slots)
            VALUES (?, ?, ?, ?, ?)
        `, [id, participantName, participantImage || null, userId, JSON.stringify(slots)]);
    }
    
    res.json({ success: true });
});

// Catch-all for SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Quest Board server running on port ${PORT}`);
    });
});
