/**
 * Security Logs Viewer
 * Retrieves and displays security logs from MongoDB Atlas
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { connectDB } from './config/database.js';
import { SecurityLog } from './models/SecurityLog.js';
import { User } from './models/User.js';

dotenv.config();

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  white: '\x1b[37m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function logHeader(message) {
  log(`\n${'='.repeat(70)}`, colors.cyan);
  log(message, colors.cyan);
  log('='.repeat(70), colors.cyan);
}

function logSection(message) {
  log(`\n${'-'.repeat(70)}`, colors.blue);
  log(message, colors.blue);
  log('-'.repeat(70), colors.blue);
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  eventType: null,
  userId: null,
  limit: 50,
  days: null,
  hours: null,
  summary: false,
  all: false
};

// Parse arguments
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  switch (arg) {
    case '--type':
    case '-t':
      options.eventType = args[++i];
      break;
    case '--user':
    case '-u':
      options.userId = args[++i];
      break;
    case '--limit':
    case '-l':
      options.limit = parseInt(args[++i]) || 50;
      break;
    case '--days':
    case '-d':
      options.days = parseInt(args[++i]) || 1;
      break;
    case '--hours':
      options.hours = parseInt(args[++i]) || 1;
      break;
    case '--summary':
    case '-s':
      options.summary = true;
      break;
    case '--all':
    case '-a':
      options.all = true;
      options.limit = 1000;
      break;
    case '--help':
      showHelp();
      process.exit(0);
  }
}

function showHelp() {
  logHeader('Security Logs Viewer - Help');
  console.log(`
Usage: node view-security-logs.js [options]

Options:
  --type, -t <type>     Filter by event type (e.g., REPLAY_DETECTED, INVALID_SIGNATURE)
  --user, -u <userId>   Filter by user ID
  --limit, -l <number>  Limit number of results (default: 50)
  --days, -d <number>   Show logs from last N days
  --hours, -h <number> Show logs from last N hours
  --summary, -s         Show summary statistics only
  --all, -a             Show all logs (limit: 1000)
  --help                Show this help message

Examples:
  node view-security-logs.js
  node view-security-logs.js --type REPLAY_DETECTED
  node view-security-logs.js --type INVALID_SIGNATURE --limit 20
  node view-security-logs.js --days 7 --summary
  node view-security-logs.js --hours 24
  node view-security-logs.js --user 692f4c332bacabbf1851b17f
  `);
}

// Format timestamp
function formatTimestamp(date) {
  return new Date(date).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  });
}

// Format event type with color
function formatEventType(eventType) {
  const colors = {
    'REPLAY_DETECTED': '\x1b[31m',      // Red
    'INVALID_SIGNATURE': '\x1b[33m',    // Yellow
    'AUTH_FAILURE': '\x1b[31m',         // Red
    'AUTH_SUCCESS': '\x1b[32m',         // Green
    'AUTH_ATTEMPT': '\x1b[36m',         // Cyan
    'KEY_EXCHANGE_FAILURE': '\x1b[33m', // Yellow
    'KEY_EXCHANGE_SUCCESS': '\x1b[32m', // Green
    'KEY_EXCHANGE_ATTEMPT': '\x1b[36m', // Cyan
    'DECRYPT_FAILURE': '\x1b[31m',      // Red
    'METADATA_ACCESS': '\x1b[34m'       // Blue
  };
  const color = colors[eventType] || '\x1b[37m';
  return `${color}${eventType}\x1b[0m`;
}

// Display a single log entry
function displayLog(logEntry, index, total) {
  log(`\n[${index + 1}/${total}]`, colors.magenta);
  log(`Event Type: ${formatEventType(logEntry.eventType)}`, colors.white);
  log(`Timestamp: ${formatTimestamp(logEntry.timestamp)}`, colors.white);
  
  if (logEntry.userId) {
    const userIdStr = typeof logEntry.userId === 'object' && logEntry.userId.username 
      ? `${logEntry.userId._id} (${logEntry.userId.username})`
      : logEntry.userId;
    log(`User ID: ${userIdStr}`, colors.white);
  }
  
  if (logEntry.ipAddress) {
    log(`IP Address: ${logEntry.ipAddress}`, colors.white);
  }
  
  if (logEntry.details && Object.keys(logEntry.details).length > 0) {
    log(`Details:`, colors.white);
    console.log(JSON.stringify(logEntry.details, null, 2));
  }
  
  log(`Log ID: ${logEntry._id}`, colors.cyan);
}

// Get summary statistics
async function getSummary() {
  logSection('Summary Statistics');
  
  try {
    // Total logs
    const totalLogs = await SecurityLog.countDocuments();
    log(`Total Logs: ${totalLogs}`, colors.green);
    
    // Logs by event type
    const logsByType = await SecurityLog.aggregate([
      {
        $group: {
          _id: '$eventType',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);
    
    log(`\nLogs by Event Type:`, colors.cyan);
    logsByType.forEach(item => {
      log(`  ${formatEventType(item._id)}: ${item.count}`, colors.white);
    });
    
    // Recent activity (last 24 hours)
    const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentLogs = await SecurityLog.countDocuments({
      timestamp: { $gte: last24Hours }
    });
    log(`\nLogs in last 24 hours: ${recentLogs}`, colors.yellow);
    
    // Most recent log
    const mostRecent = await SecurityLog.findOne().sort({ timestamp: -1 });
    if (mostRecent) {
      log(`\nMost Recent Log:`, colors.cyan);
      log(`  Type: ${formatEventType(mostRecent.eventType)}`, colors.white);
      log(`  Time: ${formatTimestamp(mostRecent.timestamp)}`, colors.white);
    }
    
    // Security events (replay attacks, invalid signatures)
    const securityEvents = await SecurityLog.countDocuments({
      eventType: { $in: ['REPLAY_DETECTED', 'INVALID_SIGNATURE', 'AUTH_FAILURE'] }
    });
    log(`\nSecurity Events (Attacks/Failures): ${securityEvents}`, colors.red);
    
  } catch (error) {
    log(`Error getting summary: ${error.message}`, colors.red);
  }
}

// Main function to retrieve and display logs
async function retrieveLogs() {
  try {
    // Connect to database
    await connectDB();
    log('✅ Connected to MongoDB Atlas', colors.green);
    
    // Build query
    const query = {};
    
    if (options.eventType) {
      query.eventType = options.eventType;
    }
    
    if (options.userId) {
      query.userId = new mongoose.Types.ObjectId(options.userId);
    }
    
    // Date filtering
    if (options.days) {
      const dateFrom = new Date(Date.now() - options.days * 24 * 60 * 60 * 1000);
      query.timestamp = { $gte: dateFrom };
    } else if (options.hours) {
      const dateFrom = new Date(Date.now() - options.hours * 60 * 60 * 1000);
      query.timestamp = { $gte: dateFrom };
    }
    
    // Show summary if requested
    if (options.summary) {
      await getSummary();
      await mongoose.connection.close();
      return;
    }
    
    // Get logs
    logHeader('Security Logs Viewer');
    
    if (Object.keys(query).length > 0) {
      log(`Query: ${JSON.stringify(query, null, 2)}`, colors.blue);
    }
    
    const logs = await SecurityLog.find(query)
      .sort({ timestamp: -1 })
      .limit(options.limit)
      .populate('userId', 'username');
    
    const totalCount = await SecurityLog.countDocuments(query);
    
    log(`\nFound ${totalCount} log(s)`, colors.green);
    log(`Displaying ${logs.length} log(s)`, colors.green);
    
    if (logs.length === 0) {
      log('\nNo logs found matching the criteria.', colors.yellow);
      await getSummary();
      await mongoose.connection.close();
      return;
    }
    
    // Display logs
    logs.forEach((logEntry, index) => {
      displayLog(logEntry, index, logs.length);
    });
    
    // Show summary at the end
    logSection('Quick Summary');
    const eventTypeCounts = {};
    logs.forEach(logEntry => {
      eventTypeCounts[logEntry.eventType] = (eventTypeCounts[logEntry.eventType] || 0) + 1;
    });
    
    Object.entries(eventTypeCounts).forEach(([type, count]) => {
      log(`${formatEventType(type)}: ${count}`, colors.white);
    });
    
    // Show full summary if requested or if showing all
    if (options.all || logs.length >= options.limit) {
      await getSummary();
    }
    
    // Close connection
    await mongoose.connection.close();
    log('\n✅ Connection closed', colors.green);
    
  } catch (error) {
    log(`\n❌ Error: ${error.message}`, colors.red);
    console.error(error);
    process.exit(1);
  }
}

// Run the script
if (args.includes('--help') || args.includes('-h')) {
  showHelp();
} else {
  retrieveLogs();
}

