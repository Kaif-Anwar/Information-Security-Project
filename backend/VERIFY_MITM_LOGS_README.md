# MITM Attack Verification Script

This script retrieves and displays security logs from MongoDB to verify that:
1. The MITM attack demonstration script worked as intended
2. Your system's security logging captured relevant events
3. Shows `INVALID_SIGNATURE` events (MITM detection)
4. Shows `KEY_EXCHANGE` events

## Quick Start

```bash
cd backend
node verify-mitm-logs.js
```

## Usage Examples

### View summary statistics only
```bash
node verify-mitm-logs.js --summary
```

### View only INVALID_SIGNATURE events (MITM attempts)
```bash
node verify-mitm-logs.js --type INVALID_SIGNATURE
```

### View key exchange events
```bash
node verify-mitm-logs.js --type KEY_EXCHANGE_ATTEMPT
```

### View logs from last 48 hours
```bash
node verify-mitm-logs.js --hours 48
```

### View all logs (up to 1000)
```bash
node verify-mitm-logs.js --all
```

### View recent MITM-related events
```bash
node verify-mitm-logs.js --type INVALID_SIGNATURE --hours 24
```

## Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--type <type>` | `-t` | Filter by event type (e.g., INVALID_SIGNATURE, KEY_EXCHANGE_ATTEMPT) |
| `--hours <number>` | `-h` | Show logs from last N hours (default: 24) |
| `--limit <number>` | `-l` | Limit number of results (default: 100) |
| `--summary` | `-s` | Show summary statistics only |
| `--all` | `-a` | Show all logs (limit: 1000) |
| `--help` | | Show help message |

## What the Script Shows

### MITM-Related Events
- **INVALID_SIGNATURE**: Signature verification failures (MITM attack detected!)
- **REPLAY_DETECTED**: Replay attacks detected

### Key Exchange Events
- **KEY_EXCHANGE_ATTEMPT**: Key exchange initiated
- **KEY_EXCHANGE_SUCCESS**: Successful key exchange
- **KEY_EXCHANGE_FAILURE**: Failed key exchange

### Other Security Events
- **AUTH_ATTEMPT**, **AUTH_SUCCESS**, **AUTH_FAILURE**: Authentication events
- **DECRYPT_FAILURE**: Message decryption failures
- **METADATA_ACCESS**: Server-side metadata access

## Understanding the Results

### ✅ MITM Detection Confirmed
If you see `INVALID_SIGNATURE` or `REPLAY_DETECTED` events, it means:
- Your system successfully detected MITM attack attempts
- The security logging is working correctly
- The attack was blocked by signature verification

### ⚠️ No MITM Events Found
If no MITM events are found, it could mean:
- No MITM attacks have been attempted on your system
- The standalone attack script (`attackerscript.py`) doesn't interact with your backend
- To test real MITM detection, you would need to perform an actual attack against your running backend server

## Example Output

```
================================================================================
MITM Attack Verification - Security Logs Viewer
================================================================================
Connecting to MongoDB...
✅ MongoDB connected successfully

--------------------------------------------------------------------------------
Summary Statistics
--------------------------------------------------------------------------------
Total Security Logs: 2499

Logs by Event Type:
  INVALID_SIGNATURE: 40
  KEY_EXCHANGE_ATTEMPT: 46
  REPLAY_DETECTED: 4

🚨 MITM-Related Events (INVALID_SIGNATURE + REPLAY_DETECTED): 44
🔐 Key Exchange Events: 46

Recent Activity (last 24 hours): 374

⚠️  Recent INVALID_SIGNATURE Events (last 24h): 40

--------------------------------------------------------------------------------
Verification Status
--------------------------------------------------------------------------------
✅ MITM Detection Confirmed!
   Found 44 MITM-related security event(s)
   Your system successfully detected and logged MITM attempts.
```

## Notes

- The script connects to MongoDB using your `.env` file configuration
- Logs are stored in the `securitylogs` collection
- The script groups logs by type for easier reading
- MITM-related events are displayed first (most important)
- Color coding helps identify security events:
  - 🔴 Red/Bold: MITM attacks detected
  - 🟢 Green: Successful operations
  - 🟡 Yellow: Warnings
  - 🔵 Blue: Information

## Related Files

- `attackerscript.py` - Standalone MITM attack demonstration script
- `view-security-logs.js` - General security logs viewer
- `models/SecurityLog.js` - Security log model definition
- `routes/keyExchange.js` - Key exchange route with logging

