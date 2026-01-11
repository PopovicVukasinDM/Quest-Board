const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('Missing SUPABASE_URL or SUPABASE_KEY environment variables!');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Password hashing
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

// Auth middleware
async function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    
    if (!token) {
        req.user = null;
        return next();
    }
    
    try {
        const { data, error } = await supabase
            .from('sessions')
            .select('user_id, users(id, username, display_name, profile_image)')
            .eq('token', token)
            .single();
        
        if (error || !data) {
            req.user = null;
        } else {
            req.user = {
                id: data.users.id,
                username: data.users.username,
                displayName: data.users.display_name,
                profileImage: data.users.profile_image
            };
        }
    } catch (err) {
        console.error('Auth error:', err);
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

app.post('/api/auth/register', async (req, res) => {
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
    
    try {
        // Check if username exists
        const { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('username', username.toLowerCase())
            .single();
        
        if (existing) {
            return res.status(400).json({ error: 'Username already taken' });
        }
        
        const hashedPassword = hashPassword(password);
        const name = displayName || username;
        
        // Create user
        const { data: newUser, error: userError } = await supabase
            .from('users')
            .insert({ username: username.toLowerCase(), password: hashedPassword, display_name: name })
            .select()
            .single();
        
        if (userError) {
            console.error('User creation error:', userError);
            return res.status(500).json({ error: 'Failed to create user' });
        }
        
        // Create session
        const token = generateToken();
        await supabase.from('sessions').insert({ user_id: newUser.id, token });
        
        res.json({
            token,
            user: {
                id: newUser.id,
                username: newUser.username,
                displayName: newUser.display_name,
                profileImage: null
            }
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('username', username.toLowerCase())
            .single();
        
        if (error || !user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        if (!verifyPassword(password, user.password)) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        const token = generateToken();
        await supabase.from('sessions').insert({ user_id: user.id, token });
        
        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                displayName: user.display_name,
                profileImage: user.profile_image
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (token) {
        await supabase.from('sessions').delete().eq('token', token);
    }
    res.json({ success: true });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json({ user: req.user || null });
});

// ============ PROFILE ROUTES ============

app.put('/api/profile', authenticateToken, requireAuth, async (req, res) => {
    const { displayName, profileImage } = req.body;
    
    try {
        await supabase
            .from('users')
            .update({ 
                display_name: displayName || req.user.displayName, 
                profile_image: profileImage || null 
            })
            .eq('id', req.user.id);
        
        res.json({ success: true });
    } catch (err) {
        console.error('Profile update error:', err);
        res.status(500).json({ error: 'Update failed' });
    }
});

app.put('/api/profile/password', authenticateToken, requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new password required' });
    }
    
    if (newPassword.length < 4) {
        return res.status(400).json({ error: 'New password must be at least 4 characters' });
    }
    
    try {
        const { data: user } = await supabase
            .from('users')
            .select('password')
            .eq('id', req.user.id)
            .single();
        
        if (!verifyPassword(currentPassword, user.password)) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        const hashedNew = hashPassword(newPassword);
        await supabase.from('users').update({ password: hashedNew }).eq('id', req.user.id);
        
        res.json({ success: true });
    } catch (err) {
        console.error('Password change error:', err);
        res.status(500).json({ error: 'Password change failed' });
    }
});

app.get('/api/profile/events', authenticateToken, requireAuth, async (req, res) => {
    try {
        // Get events user created
        const { data: created } = await supabase
            .from('events')
            .select('id, name, description, dates, start_hour, end_hour, image, tags, completed, created_at')
            .eq('creator_id', req.user.id)
            .order('created_at', { ascending: false });
        
        // Get events user participated in
        const { data: participatedAvail } = await supabase
            .from('availability')
            .select('event_id')
            .eq('user_id', req.user.id);
        
        let participated = [];
        if (participatedAvail && participatedAvail.length > 0) {
            const eventIds = participatedAvail.map(a => a.event_id);
            const { data: participatedEvents } = await supabase
                .from('events')
                .select('id, name, description, dates, start_hour, end_hour, image, tags, completed, created_at')
                .in('id', eventIds)
                .neq('creator_id', req.user.id)
                .order('created_at', { ascending: false });
            participated = participatedEvents || [];
        }
        
        // Get all event IDs to fetch participants
        const allEventIds = [...(created || []).map(e => e.id), ...participated.map(e => e.id)];
        
        // Fetch participants for all events
        let participantsMap = {};
        if (allEventIds.length > 0) {
            const { data: allAvailability } = await supabase
                .from('availability')
                .select('event_id, participant_name, participant_image')
                .in('event_id', allEventIds);
            
            if (allAvailability) {
                allAvailability.forEach(a => {
                    if (!participantsMap[a.event_id]) {
                        participantsMap[a.event_id] = [];
                    }
                    // Only add if not already in the list (avoid duplicates)
                    if (!participantsMap[a.event_id].some(p => p.name === a.participant_name)) {
                        participantsMap[a.event_id].push({
                            name: a.participant_name,
                            image: a.participant_image || null
                        });
                    }
                });
            }
        }
        
        res.json({
            created: (created || []).map(e => ({ 
                id: e.id,
                name: e.name,
                description: e.description,
                startHour: e.start_hour,
                endHour: e.end_hour,
                dates: e.dates,
                image: e.image,
                tags: e.tags || [],
                completed: e.completed || false,
                participants: participantsMap[e.id] || []
            })),
            participated: participated.map(e => ({ 
                id: e.id,
                name: e.name,
                description: e.description,
                startHour: e.start_hour,
                endHour: e.end_hour,
                dates: e.dates,
                image: e.image,
                tags: e.tags || [],
                completed: e.completed || false,
                participants: participantsMap[e.id] || []
            }))
        });
    } catch (err) {
        console.error('Profile events error:', err);
        res.status(500).json({ error: 'Failed to load events' });
    }
});

// ============ ADVENTURER ROUTES ============

app.get('/api/adventurers', authenticateToken, requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('adventurers')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        
        // Get quest board counts for each adventurer
        const adventurerNames = data.map(a => a.name);
        let questBoardCounts = {};
        let questBoardsMap = {};
        
        if (adventurerNames.length > 0) {
            const { data: availabilityData } = await supabase
                .from('availability')
                .select('participant_name, event_id')
                .in('participant_name', adventurerNames);
            
            if (availabilityData) {
                availabilityData.forEach(a => {
                    if (!questBoardCounts[a.participant_name]) {
                        questBoardCounts[a.participant_name] = new Set();
                        questBoardsMap[a.participant_name] = [];
                    }
                    questBoardCounts[a.participant_name].add(a.event_id);
                    questBoardsMap[a.participant_name].push(a.event_id);
                });
            }
        }
        
        // Get event names and tags for quest boards
        const allEventIds = [...new Set(Object.values(questBoardsMap).flat())];
        let eventInfo = {};
        if (allEventIds.length > 0) {
            const { data: events } = await supabase
                .from('events')
                .select('id, name, tags')
                .in('id', allEventIds);
            if (events) {
                events.forEach(e => eventInfo[e.id] = { name: e.name, tags: e.tags || [] });
            }
        }
        
        res.json(data.map(a => ({
            id: a.id,
            name: a.name,
            image: a.image,
            bio: a.bio,
            level: a.level,
            race: a.race,
            class: a.class,
            notes: a.notes,
            createdAt: a.created_at,
            questBoardCount: questBoardCounts[a.name] ? questBoardCounts[a.name].size : 0,
            questBoards: (questBoardsMap[a.name] || []).map(id => ({ id, name: eventInfo[id]?.name, tags: eventInfo[id]?.tags || [] }))
        })));
    } catch (err) {
        console.error('Adventurers error:', err);
        res.status(500).json({ error: 'Failed to load adventurers' });
    }
});

app.post('/api/adventurers', authenticateToken, requireAuth, async (req, res) => {
    const { name, image, bio, level, race, class: charClass, notes } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Name required' });
    }
    
    try {
        const { data, error } = await supabase
            .from('adventurers')
            .insert({ 
                user_id: req.user.id, 
                name, 
                image: image || null,
                bio: bio || null,
                level: level || null,
                race: race || null,
                class: charClass || null,
                notes: notes || null
            })
            .select()
            .single();
        
        if (error) throw error;
        
        res.json({ 
            id: data.id, 
            name: data.name, 
            image: data.image,
            bio: data.bio,
            level: data.level,
            race: data.race,
            class: data.class,
            notes: data.notes
        });
    } catch (err) {
        console.error('Create adventurer error:', err);
        res.status(500).json({ error: 'Failed to create adventurer' });
    }
});

app.put('/api/adventurers/:id', authenticateToken, requireAuth, async (req, res) => {
    const { name, image, bio, level, race, class: charClass, notes } = req.body;
    const { id } = req.params;
    
    try {
        const { data: existing } = await supabase
            .from('adventurers')
            .select('id')
            .eq('id', id)
            .eq('user_id', req.user.id)
            .single();
        
        if (!existing) {
            return res.status(404).json({ error: 'Adventurer not found' });
        }
        
        await supabase
            .from('adventurers')
            .update({ 
                name, 
                image: image || null,
                bio: bio || null,
                level: level || null,
                race: race || null,
                class: charClass || null,
                notes: notes || null
            })
            .eq('id', id);
        
        res.json({ success: true });
    } catch (err) {
        console.error('Update adventurer error:', err);
        res.status(500).json({ error: 'Update failed' });
    }
});

// Get public adventurer info (for viewing other players' characters)
app.get('/api/adventurers/public/:name', async (req, res) => {
    const { name } = req.params;
    
    try {
        const { data: availability } = await supabase
            .from('availability')
            .select('participant_name, participant_image, user_id')
            .eq('participant_name', decodeURIComponent(name))
            .limit(1);
        
        if (!availability || availability.length === 0) {
            return res.status(404).json({ error: 'Adventurer not found' });
        }
        
        const userId = availability[0].user_id;
        
        // If there's a user_id, try to get full adventurer details
        if (userId) {
            const { data: adventurer } = await supabase
                .from('adventurers')
                .select('name, image, bio, level, race, class, notes')
                .eq('user_id', userId)
                .eq('name', decodeURIComponent(name))
                .single();
            
            if (adventurer) {
                return res.json(adventurer);
            }
        }
        
        // Fallback to basic info from availability
        res.json({
            name: availability[0].participant_name,
            image: availability[0].participant_image
        });
    } catch (err) {
        console.error('Public adventurer error:', err);
        res.status(500).json({ error: 'Failed to load adventurer' });
    }
});

app.delete('/api/adventurers/:id', authenticateToken, requireAuth, async (req, res) => {
    const { id } = req.params;
    
    try {
        const { data: existing } = await supabase
            .from('adventurers')
            .select('id')
            .eq('id', id)
            .eq('user_id', req.user.id)
            .single();
        
        if (!existing) {
            return res.status(404).json({ error: 'Adventurer not found' });
        }
        
        await supabase.from('adventurers').delete().eq('id', id);
        
        res.json({ success: true });
    } catch (err) {
        console.error('Delete adventurer error:', err);
        res.status(500).json({ error: 'Delete failed' });
    }
});

// ============ EVENT ROUTES ============

app.post('/api/events', authenticateToken, async (req, res) => {
    const { name, description, dates, startHour, endHour, image, tags } = req.body;
    
    if (!name || !dates || dates.length === 0) {
        return res.status(400).json({ error: 'Name and dates are required' });
    }
    
    try {
        const eventId = crypto.randomBytes(4).toString('hex');
        const creatorId = req.user ? req.user.id : null;
        
        const { error } = await supabase.from('events').insert({
            id: eventId,
            name,
            description: description || '',
            dates: dates,
            start_hour: startHour || 9,
            end_hour: endHour || 22,
            creator_id: creatorId,
            image: image || null,
            tags: tags || [],
            completed: false
        });
        
        if (error) throw error;
        
        res.json({ id: eventId, url: `/event/${eventId}` });
    } catch (err) {
        console.error('Create event error:', err);
        res.status(500).json({ error: 'Failed to create event' });
    }
});

app.get('/api/events/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
        const { data: event, error: eventError } = await supabase
            .from('events')
            .select('*')
            .eq('id', id)
            .single();
        
        if (eventError || !event) {
            return res.status(404).json({ error: 'Event not found' });
        }
        
        const { data: availData } = await supabase
            .from('availability')
            .select('*')
            .eq('event_id', id);
        
        const participants = [];
        const availability = {};
        const participantImages = {};
        
        (availData || []).forEach(row => {
            participants.push(row.participant_name);
            availability[row.participant_name] = row.slots;
            if (row.participant_image) {
                participantImages[row.participant_name] = row.participant_image;
            }
        });
        
        res.json({
            id: event.id,
            name: event.name,
            description: event.description,
            dates: event.dates,
            startHour: event.start_hour,
            endHour: event.end_hour,
            creatorId: event.creator_id,
            createdAt: event.created_at,
            image: event.image,
            tags: event.tags || [],
            completed: event.completed || false,
            allowComments: event.allow_comments !== false,
            notifyComments: event.notify_comments !== false,
            participants,
            participantImages,
            availability
        });
    } catch (err) {
        console.error('Get event error:', err);
        res.status(500).json({ error: 'Failed to load event' });
    }
});

// Update event (only creator can edit)
app.put('/api/events/:id', authenticateToken, requireAuth, async (req, res) => {
    const { id } = req.params;
    const { name, description, dates, startHour, endHour, image, tags, completed, allowComments, notifyComments } = req.body;
    
    try {
        // Check if user is the creator
        const { data: event } = await supabase
            .from('events')
            .select('creator_id')
            .eq('id', id)
            .single();
        
        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }
        
        if (event.creator_id !== req.user.id) {
            return res.status(403).json({ error: 'Only the creator can edit this event' });
        }
        
        await supabase
            .from('events')
            .update({
                name,
                description: description || '',
                dates,
                start_hour: startHour,
                end_hour: endHour,
                image: image || null,
                tags: tags || [],
                completed: completed || false,
                allow_comments: allowComments !== false,
                notify_comments: notifyComments !== false
            })
            .eq('id', id);
        
        res.json({ success: true });
    } catch (err) {
        console.error('Update event error:', err);
        res.status(500).json({ error: 'Failed to update event' });
    }
});

app.post('/api/events/:id/availability', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { participantName, participantImage, slots } = req.body;
    
    if (!participantName) {
        return res.status(400).json({ error: 'Participant name required' });
    }
    
    try {
        // Check if event exists
        const { data: event } = await supabase
            .from('events')
            .select('id')
            .eq('id', id)
            .single();
        
        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }
        
        const userId = req.user ? req.user.id : null;
        
        // Upsert availability
        const { error } = await supabase
            .from('availability')
            .upsert({
                event_id: id,
                participant_name: participantName,
                participant_image: participantImage || null,
                user_id: userId,
                slots: slots,
                updated_at: new Date().toISOString()
            }, {
                onConflict: 'event_id,participant_name'
            });
        
        if (error) throw error;
        
        res.json({ success: true });
    } catch (err) {
        console.error('Save availability error:', err);
        res.status(500).json({ error: 'Failed to save availability' });
    }
});

// Delete availability (for switching adventurers)
app.delete('/api/events/:id/availability/:participantName', authenticateToken, async (req, res) => {
    const { id, participantName } = req.params;
    
    try {
        const { error } = await supabase
            .from('availability')
            .delete()
            .eq('event_id', id)
            .eq('participant_name', decodeURIComponent(participantName));
        
        if (error) throw error;
        
        res.json({ success: true });
    } catch (err) {
        console.error('Delete availability error:', err);
        res.status(500).json({ error: 'Failed to delete availability' });
    }
});

// Delete event (only creator can delete)
app.delete('/api/events/:id', authenticateToken, requireAuth, async (req, res) => {
    const { id } = req.params;
    
    try {
        // Check if user is the creator
        const { data: event } = await supabase
            .from('events')
            .select('creator_id')
            .eq('id', id)
            .single();
        
        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }
        
        if (event.creator_id !== req.user.id) {
            return res.status(403).json({ error: 'Only the creator can delete this event' });
        }
        
        // Delete all availability for this event first
        await supabase.from('availability').delete().eq('event_id', id);
        
        // Delete the event
        await supabase.from('events').delete().eq('id', id);
        
        res.json({ success: true });
    } catch (err) {
        console.error('Delete event error:', err);
        res.status(500).json({ error: 'Failed to delete event' });
    }
});

// Delete user profile and all associated data
app.delete('/api/profile', authenticateToken, requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get all events created by user
        const { data: userEvents } = await supabase
            .from('events')
            .select('id')
            .eq('creator_id', userId);
        
        // Delete availability for all user's events
        if (userEvents && userEvents.length > 0) {
            const eventIds = userEvents.map(e => e.id);
            await supabase.from('availability').delete().in('event_id', eventIds);
        }
        
        // Delete all events created by user
        await supabase.from('events').delete().eq('creator_id', userId);
        
        // Delete all adventurers
        await supabase.from('adventurers').delete().eq('user_id', userId);
        
        // Delete all sessions
        await supabase.from('sessions').delete().eq('user_id', userId);
        
        // Delete user
        await supabase.from('users').delete().eq('id', userId);
        
        res.json({ success: true });
    } catch (err) {
        console.error('Delete profile error:', err);
        res.status(500).json({ error: 'Failed to delete profile' });
    }
});

// ============ COMMENT ROUTES ============

// Get comments for an event
app.get('/api/events/:id/comments', async (req, res) => {
    const { id } = req.params;
    try {
        const { data, error } = await supabase
            .from('comments')
            .select('*')
            .eq('event_id', id)
            .order('created_at', { ascending: true });
        
        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        console.error('Get comments error:', err);
        res.status(500).json({ error: 'Failed to load comments' });
    }
});

// Add a comment
app.post('/api/events/:id/comments', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { adventurerName, content, mentions } = req.body;
    
    if (!adventurerName || !content) {
        return res.status(400).json({ error: 'Adventurer name and content are required' });
    }
    
    try {
        // Check if event exists and allows comments
        const { data: event } = await supabase
            .from('events')
            .select('allow_comments, notify_comments')
            .eq('id', id)
            .single();
        
        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }
        
        if (event.allow_comments === false) {
            return res.status(403).json({ error: 'Comments are disabled for this quest board' });
        }
        
        // Get adventurer image
        const { data: adventurer } = await supabase
            .from('adventurers')
            .select('image')
            .eq('name', adventurerName)
            .eq('user_id', req.user?.id)
            .single();
        
        // Insert comment
        const { data: comment, error } = await supabase
            .from('comments')
            .insert({
                event_id: id,
                adventurer_name: adventurerName,
                adventurer_image: adventurer?.image || null,
                user_id: req.user?.id || null,
                content,
                mentions: mentions || []
            })
            .select()
            .single();
        
        if (error) throw error;
        
        // Create notifications for mentioned adventurers if enabled
        if (event.notify_comments !== false && mentions && mentions.length > 0) {
            // Get user IDs for mentioned adventurers
            const { data: availability } = await supabase
                .from('availability')
                .select('user_id, participant_name')
                .eq('event_id', id)
                .in('participant_name', mentions);
            
            if (availability) {
                const notificationData = availability
                    .filter(a => a.user_id && a.participant_name !== adventurerName)
                    .map(a => ({
                        user_id: a.user_id,
                        type: 'mention',
                        event_id: id,
                        comment_id: comment.id,
                        from_adventurer: adventurerName
                    }));
                
                if (notificationData.length > 0) {
                    await supabase.from('notifications').insert(notificationData);
                }
            }
        }
        
        res.json(comment);
    } catch (err) {
        console.error('Add comment error:', err);
        res.status(500).json({ error: 'Failed to add comment' });
    }
});

// Update a comment
app.put('/api/comments/:commentId', authenticateToken, async (req, res) => {
    const { commentId } = req.params;
    const { content, mentions } = req.body;
    
    try {
        // Check if user owns the comment
        const { data: comment } = await supabase
            .from('comments')
            .select('user_id, event_id')
            .eq('id', commentId)
            .single();
        
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found' });
        }
        
        if (comment.user_id !== req.user?.id) {
            return res.status(403).json({ error: 'You can only edit your own comments' });
        }
        
        const { error } = await supabase
            .from('comments')
            .update({
                content,
                mentions: mentions || [],
                edited: true,
                updated_at: new Date().toISOString()
            })
            .eq('id', commentId);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        console.error('Update comment error:', err);
        res.status(500).json({ error: 'Failed to update comment' });
    }
});

// Delete a comment
app.delete('/api/comments/:commentId', authenticateToken, async (req, res) => {
    const { commentId } = req.params;
    
    try {
        // Check if user owns the comment or is event owner
        const { data: comment } = await supabase
            .from('comments')
            .select('user_id, event_id')
            .eq('id', commentId)
            .single();
        
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found' });
        }
        
        const { data: event } = await supabase
            .from('events')
            .select('creator_id')
            .eq('id', comment.event_id)
            .single();
        
        if (comment.user_id !== req.user?.id && event?.creator_id !== req.user?.id) {
            return res.status(403).json({ error: 'You can only delete your own comments' });
        }
        
        // Delete notifications first
        await supabase.from('notifications').delete().eq('comment_id', commentId);
        
        // Delete comment
        const { error } = await supabase
            .from('comments')
            .delete()
            .eq('id', commentId);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        console.error('Delete comment error:', err);
        res.status(500).json({ error: 'Failed to delete comment' });
    }
});

// ============ NOTIFICATION ROUTES ============

// Get unread notification count
app.get('/api/notifications/count', authenticateToken, requireAuth, async (req, res) => {
    try {
        const { count, error } = await supabase
            .from('notifications')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id)
            .eq('read', false);
        
        if (error) throw error;
        res.json({ count: count || 0 });
    } catch (err) {
        console.error('Get notification count error:', err);
        res.status(500).json({ error: 'Failed to get notification count' });
    }
});

// Get all notifications
app.get('/api/notifications', authenticateToken, requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('notifications')
            .select(`
                *,
                comments (
                    content,
                    adventurer_name,
                    created_at
                ),
                events (
                    name,
                    image
                )
            `)
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false })
            .limit(50);
        
        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        console.error('Get notifications error:', err);
        res.status(500).json({ error: 'Failed to load notifications' });
    }
});

// Mark notifications as read for an event
app.put('/api/notifications/read/:eventId', authenticateToken, requireAuth, async (req, res) => {
    const { eventId } = req.params;
    
    try {
        const { error } = await supabase
            .from('notifications')
            .update({ read: true })
            .eq('user_id', req.user.id)
            .eq('event_id', eventId);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        console.error('Mark notifications read error:', err);
        res.status(500).json({ error: 'Failed to mark notifications as read' });
    }
});

// Mark all notifications as read
app.put('/api/notifications/read-all', authenticateToken, requireAuth, async (req, res) => {
    try {
        const { error } = await supabase
            .from('notifications')
            .update({ read: true })
            .eq('user_id', req.user.id);
        
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        console.error('Mark all notifications read error:', err);
        res.status(500).json({ error: 'Failed to mark notifications as read' });
    }
});

// Catch-all for SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Quest Board server running on port ${PORT}`);
    console.log('Connected to Supabase');
});
