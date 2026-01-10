const express = require('express');
const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const { nanoid } = require('nanoid');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DATABASE_PATH || './quest-board.db';

let db = null;

// Initialize database
async function initDatabase() {
    const SQL = await initSqlJs();
    
    // Try to load existing database
    if (fs.existsSync(DB_PATH)) {
        const fileBuffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(fileBuffer);
    } else {
        db = new SQL.Database();
    }
    
    // Create tables
    db.run(`
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            dates TEXT NOT NULL,
            start_hour INTEGER DEFAULT 10,
            end_hour INTEGER DEFAULT 22,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS availability (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            participant_name TEXT NOT NULL,
            slot_key TEXT NOT NULL,
            note TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events(id),
            UNIQUE(event_id, participant_name, slot_key)
        )
    `);
    
    db.run(`CREATE INDEX IF NOT EXISTS idx_availability_event ON availability(event_id)`);
    
    saveDatabase();
    console.log('✓ Database initialized');
}

// Save database to file
function saveDatabase() {
    if (db) {
        const data = db.export();
        const buffer = Buffer.from(data);
        fs.writeFileSync(DB_PATH, buffer);
    }
}

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// API Routes

// Create a new event
app.post('/api/events', (req, res) => {
    try {
        const { name, description, dates, startHour, endHour } = req.body;
        
        if (!name || !dates || !Array.isArray(dates) || dates.length === 0) {
            return res.status(400).json({ error: 'Name and dates are required' });
        }

        const id = nanoid(10);
        
        db.run(`
            INSERT INTO events (id, name, description, dates, start_hour, end_hour)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [id, name, description || '', JSON.stringify(dates), startHour || 10, endHour || 22]);
        
        saveDatabase();
        res.json({ id, url: `/event/${id}` });
    } catch (error) {
        console.error('Error creating event:', error);
        res.status(500).json({ error: 'Failed to create event' });
    }
});

// Get event details
app.get('/api/events/:id', (req, res) => {
    try {
        const { id } = req.params;
        
        const eventResult = db.exec('SELECT * FROM events WHERE id = ?', [id]);
        
        if (eventResult.length === 0 || eventResult[0].values.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }

        const eventRow = eventResult[0].values[0];
        const columns = eventResult[0].columns;
        const event = {};
        columns.forEach((col, i) => event[col] = eventRow[i]);

        // Get all availability for this event
        const availResult = db.exec(`
            SELECT participant_name, slot_key, note 
            FROM availability 
            WHERE event_id = ?
        `, [id]);

        // Group availability by participant
        const availability = {};
        const participants = new Set();
        
        if (availResult.length > 0) {
            availResult[0].values.forEach(row => {
                const [participant_name, slot_key, note] = row;
                participants.add(participant_name);
                if (!availability[participant_name]) {
                    availability[participant_name] = {};
                }
                availability[participant_name][slot_key] = {
                    available: true,
                    note: note || ''
                };
            });
        }

        res.json({
            id: event.id,
            name: event.name,
            description: event.description,
            dates: JSON.parse(event.dates),
            startHour: event.start_hour,
            endHour: event.end_hour,
            participants: Array.from(participants),
            availability
        });
    } catch (error) {
        console.error('Error fetching event:', error);
        res.status(500).json({ error: 'Failed to fetch event' });
    }
});

// Update availability for a participant
app.post('/api/events/:id/availability', (req, res) => {
    try {
        const { id } = req.params;
        const { participantName, slots } = req.body;

        if (!participantName || !slots) {
            return res.status(400).json({ error: 'Participant name and slots are required' });
        }

        // Verify event exists
        const eventResult = db.exec('SELECT id FROM events WHERE id = ?', [id]);
        if (eventResult.length === 0 || eventResult[0].values.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }

        // Delete existing availability for this participant
        db.run('DELETE FROM availability WHERE event_id = ? AND participant_name = ?', [id, participantName]);

        // Insert new availability
        for (const [slotKey, data] of Object.entries(slots)) {
            if (data.available) {
                db.run(`
                    INSERT INTO availability (event_id, participant_name, slot_key, note)
                    VALUES (?, ?, ?, ?)
                `, [id, participantName, slotKey, data.note || '']);
            }
        }

        saveDatabase();
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating availability:', error);
        res.status(500).json({ error: 'Failed to update availability' });
    }
});

// Serve the app for any non-API route (SPA support)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`⚔️  Quest Board running at http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
});
