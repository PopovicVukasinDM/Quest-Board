const express = require('express');
const path = require('path');
const crypto = require('crypto');
const initSqlJs = require('sql.js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let db;

// Simple password hashing (using crypto since bcrypt requires native modules)
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

// Generate session token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Initialize database
async function initDatabase() {
    const SQL = await initSqlJs();
    db = new SQL.Database();
    
    // Users table
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
    
    // Sessions table
    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
    
    // Adventurers table (user's saved characters)
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
    
    // Events table
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
    
    // Availability table
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
    
    const session = db.exec(`
        SELECT s.user_id, u.username, u.display_name, u.profile_image 
        FROM sessions s 
        JOIN users u ON s.user_id = u.id 
        WHERE s.token = ?
    `, [token]);
    
    if (session.length === 0 || session[0].values.length === 0) {
        req.user = null;
        return next();
    }
    
    const [userId, username, displayName, profileImage] = session[0].values[0];
    req.user = { id: userId, username, displayName, profileImage };
    next();
}

// Require auth middleware
function requireAuth(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
}

// ============ AUTH ROUTES ============

// Register
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
    
    // Check if username exists
    const existing = db.exec(`SELECT id FROM users WHERE username = ?`, [username.toLowerCase()]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        return res.status(400).json({ error: 'Username already taken' });
    }
    
    const hashedPassword = hashPassword(password);
    const name = displayName || username;
    
    db.run(`INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)`, 
        [username.toLowerCase(), hashedPassword, name]);
    
    const userId = db.exec(`SELECT last_insert_rowid()`)[0].values[0][0];
    const token = generateToken();
    
    db.run(`INSERT INTO sessions (user_id, token) VALUES (?, ?)`, [userId, token]);
    
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

// Login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    
    const result = db.exec(`SELECT id, username, password, display_name, profile_image FROM users WHERE username = ?`, 
        [username.toLowerCase()]);
    
    if (result.length === 0 || result[0].values.length === 0) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const [userId, uname, hashedPassword, displayName, profileImage] = result[0].values[0];
    
    if (!verifyPassword(password, hashedPassword)) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const token = generateToken();
    db.run(`INSERT INTO sessions (user_id, token) VALUES (?, ?)`, [userId, token]);
    
    res.json({
        token,
        user: {
            id: userId,
            username: uname,
            displayName,
            profileImage
        }
    });
});

// Logout
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (token) {
        db.run(`DELETE FROM sessions WHERE token = ?`, [token]);
    }
    res.json({ success: true });
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
    if (!req.user) {
        return res.json({ user: null });
    }
    res.json({ user: req.user });
});

// ============ PROFILE ROUTES ============

// Update profile
app.put('/api/profile', authenticateToken, requireAuth, (req, res) => {
    const { displayName, profileImage } = req.body;
    
    db.run(`UPDATE users SET display_name = ?, profile_image = ? WHERE id = ?`,
        [displayName || req.user.displayName, profileImage || null, req.user.id]);
    
    res.json({ success: true });
});

// Change password
app.put('/api/profile/password', authenticateToken, requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new password required' });
    }
    
    if (newPassword.length < 4) {
        return res.status(400).json({ error: 'New password must be at least 4 characters' });
    }
    
    // Verify current password
    const result = db.exec(`SELECT password FROM users WHERE id = ?`, [req.user.id]);
    const storedPassword = result[0].values[0][0];
    
    if (!verifyPassword(currentPassword, storedPassword)) {
        return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    const hashedNew = hashPassword(newPassword);
    db.run(`UPDATE users SET password = ? WHERE id = ?`, [hashedNew, req.user.id]);
    
    res.json({ success: true });
});

// Get user's quest boards
app.get('/api/profile/events', authenticateToken, requireAuth, (req, res) => {
    // Get events user created
    const created = db.exec(`
        SELECT id, name, description, dates, created_at 
        FROM events WHERE creator_id = ?
        ORDER BY created_at DESC
    `, [req.user.id]);
    
    // Get events user participated in
    const participated = db.exec(`
        SELECT DISTINCT e.id, e.name, e.description, e.dates, e.created_at
        FROM events e
        JOIN availability a ON e.id = a.event_id
        WHERE a.user_id = ? AND e.creator_id != ?
        ORDER BY e.created_at DESC
    `, [req.user.id, req.user.id]);
    
    const formatEvents = (result) => {
        if (result.length === 0) return [];
        return result[0].values.map(row => ({
            id: row[0],
            name: row[1],
            description: row[2],
            dates: JSON.parse(row[3]),
            createdAt: row[4]
        }));
    };
    
    res.json({
        created: formatEvents(created),
        participated: formatEvents(participated)
    });
});

// ============ ADVENTURER ROUTES ============

// Get user's adventurers
app.get('/api/adventurers', authenticateToken, requireAuth, (req, res) => {
    const result = db.exec(`
        SELECT id, name, image, created_at 
        FROM adventurers WHERE user_id = ?
        ORDER BY created_at DESC
    `, [req.user.id]);
    
    if (result.length === 0) {
        return res.json([]);
    }
    
    const adventurers = result[0].values.map(row => ({
        id: row[0],
        name: row[1],
        image: row[2],
        createdAt: row[3]
    }));
    
    res.json(adventurers);
});

// Create adventurer
app.post('/api/adventurers', authenticateToken, requireAuth, (req, res) => {
    const { name, image } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Name required' });
    }
    
    db.run(`INSERT INTO adventurers (user_id, name, image) VALUES (?, ?, ?)`,
        [req.user.id, name, image || null]);
    
    const id = db.exec(`SELECT last_insert_rowid()`)[0].values[0][0];
    
    res.json({ id, name, image });
});

// Update adventurer
app.put('/api/adventurers/:id', authenticateToken, requireAuth, (req, res) => {
    const { name, image } = req.body;
    const { id } = req.params;
    
    // Verify ownership
    const check = db.exec(`SELECT id FROM adventurers WHERE id = ? AND user_id = ?`, [id, req.user.id]);
    if (check.length === 0 || check[0].values.length === 0) {
        return res.status(404).json({ error: 'Adventurer not found' });
    }
    
    db.run(`UPDATE adventurers SET name = ?, image = ? WHERE id = ?`,
        [name, image || null, id]);
    
    res.json({ success: true });
});

// Delete adventurer
app.delete('/api/adventurers/:id', authenticateToken, requireAuth, (req, res) => {
    const { id } = req.params;
    
    // Verify ownership
    const check = db.exec(`SELECT id FROM adventurers WHERE id = ? AND user_id = ?`, [id, req.user.id]);
    if (check.length === 0 || check[0].values.length === 0) {
        return res.status(404).json({ error: 'Adventurer not found' });
    }
    
    db.run(`DELETE FROM adventurers WHERE id = ?`, [id]);
    
    res.json({ success: true });
});

// ============ EVENT ROUTES ============

// Create event
app.post('/api/events', authenticateToken, (req, res) => {
    const { name, description, dates, startHour, endHour } = req.body;
    
    if (!name || !dates || dates.length === 0) {
        return res.status(400).json({ error: 'Name and dates are required' });
    }
    
    const eventId = crypto.randomBytes(4).toString('hex');
    const creatorId = req.user ? req.user.id : null;
    
    db.run(`
        INSERT INTO events (id, name, description, dates, start_hour, end_hour, creator_id)
        VALUES (?, ?, ?, ?, ?, ?)
    `, [eventId, name, description || '', JSON.stringify(dates), startHour || 9, endHour || 22, creatorId]);
    
    res.json({ 
        id: eventId, 
        url: `/event/${eventId}` 
    });
});

// Get event
app.get('/api/events/:id', (req, res) => {
    const { id } = req.params;
    
    const eventResult = db.exec(`
        SELECT id, name, description, dates, start_hour, end_hour, creator_id, created_at
        FROM events WHERE id = ?
    `, [id]);
    
    if (eventResult.length === 0 || eventResult[0].values.length === 0) {
        return res.status(404).json({ error: 'Event not found' });
    }
    
    const [eventId, name, description, dates, startHour, endHour, creatorId, createdAt] = eventResult[0].values[0];
    
    const availResult = db.exec(`
        SELECT participant_name, participant_image, user_id, slots
        FROM availability WHERE event_id = ?
    `, [id]);
    
    const participants = [];
    const availability = {};
    const participantImages = {};
    
    if (availResult.length > 0) {
        availResult[0].values.forEach(row => {
            const [participantName, participantImage, userId, slots] = row;
            participants.push(participantName);
            availability[participantName] = JSON.parse(slots);
            if (participantImage) {
                participantImages[participantName] = participantImage;
            }
        });
    }
    
    res.json({
        id: eventId,
        name,
        description,
        dates: JSON.parse(dates),
        startHour,
        endHour,
        creatorId,
        createdAt,
        participants,
        participantImages,
        availability
    });
});

// Save availability
app.post('/api/events/:id/availability', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { participantName, participantImage, slots } = req.body;
    
    if (!participantName) {
        return res.status(400).json({ error: 'Participant name required' });
    }
    
    // Check if event exists
    const eventCheck = db.exec(`SELECT id FROM events WHERE id = ?`, [id]);
    if (eventCheck.length === 0 || eventCheck[0].values.length === 0) {
        return res.status(404).json({ error: 'Event not found' });
    }
    
    const userId = req.user ? req.user.id : null;
    
    // Check if participant already exists
    const existing = db.exec(`SELECT id FROM availability WHERE event_id = ? AND participant_name = ?`, [id, participantName]);
    
    if (existing.length > 0 && existing[0].values.length > 0) {
        db.run(`
            UPDATE availability 
            SET slots = ?, participant_image = ?, user_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE event_id = ? AND participant_name = ?
        `, [JSON.stringify(slots), participantImage || null, userId, id, participantName]);
    } else {
        db.run(`
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
