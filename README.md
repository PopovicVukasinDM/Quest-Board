# ⚔️ Quest Board

A D&D-themed session scheduler like When2Meet, but with the ability to add **notes to individual time slots**.

Perfect for coordinating game sessions where players might have conditions like:
- "Available but joining remotely"
- "Might need a 15-minute dinner break"
- "Can only play until 10pm"

## Features

- 📅 Create events with multiple date options
- 👥 Share a link with your party
- ✏️ Each player marks their availability
- 📜 Add contextual notes to any time slot
- 🎨 Fantasy tavern notice board aesthetic


## Local Development

```bash
# Install dependencies
npm install

# Run the server
npm start

# Open http://localhost:3000
```

## How It Works

1. **Create an Event**: Set the name, select possible dates, and choose the time range
2. **Share the Link**: Send the unique URL to your party members
3. **Mark Availability**: Each person clicks slots to mark when they're free
4. **Add Notes**: Right-click (or long-press on mobile) any available slot to add context
5. **Find the Best Time**: The heat map shows where most people overlap

## Tech Stack

- **Backend**: Node.js + Express
- **Database**: SQLite (file-based, no setup needed)
- **Frontend**: React (via CDN, no build step)
- **Styling**: Custom CSS with fantasy theme

## File Structure

```
quest-board/
├── server.js          # Express backend with API routes
├── package.json       # Dependencies
├── public/
│   └── index.html     # React frontend (single file)
└── quest-board.db     # SQLite database (created automatically)
```

## API Endpoints

- `POST /api/events` - Create a new event
- `GET /api/events/:id` - Get event details and all availability
- `POST /api/events/:id/availability` - Update a participant's availability

## Environment Variables

- `PORT` - Server port (default: 3000)
- `DATABASE_PATH` - SQLite database path (default: ./quest-board.db)

## License

MIT - Use it for your campaigns!

---

*May your schedules align and your rolls be nat 20s* 🎲
