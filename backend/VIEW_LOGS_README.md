# Security Logs Viewer

A script to retrieve and display security logs from MongoDB Atlas.

## Quick Start

```bash
cd backend
node view-security-logs.js
```

## Usage Examples

### View recent logs (default: 50)
```bash
node view-security-logs.js
```

### View summary statistics only
```bash
node view-security-logs.js --summary
```

### Filter by event type
```bash
# View all replay attacks
node view-security-logs.js --type REPLAY_DETECTED

# View all invalid signatures
node view-security-logs.js --type INVALID_SIGNATURE

# View authentication failures
node view-security-logs.js --type AUTH_FAILURE
```

### Filter by time period
```bash
# Last 24 hours
node view-security-logs.js --hours 24

# Last 7 days
node view-security-logs.js --days 7

# Last 7 days summary
node view-security-logs.js --days 7 --summary
```

### Filter by user
```bash
node view-security-logs.js --user <userId>
```

### Limit results
```bash
# Show only 10 logs
node view-security-logs.js --limit 10

# Show all logs (up to 1000)
node view-security-logs.js --all
```

### Combine filters
```bash
# Replay attacks from last 24 hours
node view-security-logs.js --type REPLAY_DETECTED --hours 24

# Invalid signatures, limit 20
node view-security-logs.js --type INVALID_SIGNATURE --limit 20
```

## Available Event Types

- `REPLAY_DETECTED` - Replay attack detected
- `INVALID_SIGNATURE` - Invalid signature detected
- `AUTH_ATTEMPT` - Authentication attempt
- `AUTH_SUCCESS` - Successful authentication
- `AUTH_FAILURE` - Failed authentication
- `KEY_EXCHANGE_ATTEMPT` - Key exchange attempt
- `KEY_EXCHANGE_SUCCESS` - Successful key exchange
- `KEY_EXCHANGE_FAILURE` - Failed key exchange
- `DECRYPT_FAILURE` - Message decryption failure
- `METADATA_ACCESS` - Server-side metadata access

## Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--type <type>` | `-t` | Filter by event type |
| `--user <userId>` | `-u` | Filter by user ID |
| `--limit <number>` | `-l` | Limit number of results (default: 50) |
| `--days <number>` | `-d` | Show logs from last N days |
| `--hours <number>` | | Show logs from last N hours |
| `--summary` | `-s` | Show summary statistics only |
| `--all` | `-a` | Show all logs (limit: 1000) |
| `--help` | | Show help message |

## Output Format

Each log entry shows:
- **Event Type** - Color-coded event type
- **Timestamp** - When the event occurred
- **User ID** - Associated user (if any)
- **IP Address** - Client IP address
- **Details** - Event-specific information (JSON)
- **Log ID** - Unique log identifier

## Summary Statistics

When using `--summary` or viewing all logs, you'll see:
- Total number of logs
- Logs grouped by event type
- Recent activity (last 24 hours)
- Most recent log
- Security events count (attacks/failures)

## Notes

- Logs are stored in MongoDB Atlas cloud database
- Collection name: `securitylogs`
- Database: `e2ee_messaging`
- Connection is automatically established using `.env` configuration

