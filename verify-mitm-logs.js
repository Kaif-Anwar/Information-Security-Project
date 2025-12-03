#!/usr/bin/env node
/**
 * MITM Attack Verification Script
 * 
 * This script retrieves security logs from MongoDB to verify:
 * 1. That the MITM attack demonstration script worked
 * 2. That the system's security logging captured relevant events
 * 3. Shows INVALID_SIGNATURE events (MITM detection)
 * 4. Shows KEY_EXCHANGE events
 * 
 * Usage:
 *   node verify-mitm-logs.js
 *   node verify-mitm-logs.js --hours 24
 *   node verify-mitm-logs.js --type INVALID_SIGNATURE
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config({ path: join(__dirname, 'backend', '.env') });

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
  bold: '\x1b[1m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function logHeader(message) {
  log(`\n${'='.repeat(80)}`, colors.cyan);
  log(message, colors.cyan + colors.bold);
  log('='.repeat(80), colors.cyan);
}

function logSection(message) {
  log(`\n${'-'.repeat(80)}`, colors.blue);
  log(message, colors.blue + colors.bold);
  log('-'.repeat(80), colors.blue);
}

function logSubSection(message) {
  log(`\n${'─'.repeat(80)}`, colors.yellow);
  log(message, colors.yellow);
  log('─'.repeat(80), colors.yellow);
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  eventType: null,
  hours: 24,  // Default: last 24 hours
  limit: 100,
  summary: false,
  all: false
};

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  switch (arg) {
    case '--type':
    case '-t':
      options.eventType = args[++i];
      break;
    case '--hours':
    case '-h':
      options.hours = parseInt(args[++i]) || 24;
      break;
    case '--limit':
    case '-l':
      options.limit = parseInt(args[++i]) || 100;
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
  logHeader('MITM Logs Verification Script - Help');
  console.log(`
Usage: node verify-mitm-logs.js [options]

Options:
  --type, -t <type>     Filter by event type (e.g., INVALID_SIGNATURE, KEY_EXCHANGE_ATTEMPT)
  --hours, -h <number> Show logs from last N hours (default: 24)
  --limit, -l <number>  Limit number of results (default: 100)
  --summary, -s         Show summary statistics only
  --all, -a             Show all logs (limit: 1000)
  --help                Show this help message

Examples:
  node verify-mitm-logs.js
  node verify-mitm-logs.js --type INVALID_SIGNATURE
  node verify-mitm-logs.js --hours 48
  node verify-mitm-logs.js --summary
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
  const eventColors = {
    'INVALID_SIGNATURE': colors.red + colors.bold,      // Red - MITM detected!
    'KEY_EXCHANGE_FAILURE': colors.red,                 // Red
    'KEY_EXCHANGE_SUCCESS': colors.green,               // Green
    'KEY_EXCHANGE_ATTEMPT': colors.cyan,                // Cyan
    'REPLAY_DETECTED': colors.red + colors.bold,        // Red - Attack!
    'AUTH_FAILURE': colors.red,                        // Red
    'AUTH_SUCCESS': colors.green,                       // Green
    'AUTH_ATTEMPT': colors.cyan,                        // Cyan
    'DECRYPT_FAILURE': colors.yellow,                  // Yellow
    'METADATA_ACCESS': colors.blue                      // Blue
  };
  const color = eventColors[eventType] || colors.white;
  return `${color}${eventType}${colors.reset}`;
}

// Display a single log entry
function displayLog(logEntry, index, total) {
  log(`\n[${index + 1}/${total}]`, colors.magenta);
  log(`Event Type: ${formatEventType(logEntry.eventType)}`, colors.white);
  log(`Timestamp: ${formatTimestamp(logEntry.timestamp)}`, colors.white);
  
  if (logEntry.userId) {
    const userIdStr = typeof logEntry.userId === 'object' && logEntry.userId.username 
      ? `${logEntry.userId._id} (${logEntry.userId.username})`
      : logEntry.userId.toString();
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
async function getSummary(SecurityLog) {
  logSection('Summary Statistics');
  
  try {
    // Total logs
    const totalLogs = await SecurityLog.countDocuments();
    log(`Total Security Logs: ${totalLogs}`, colors.green);
    
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
    
    // MITM-related events (INVALID_SIGNATURE, REPLAY_DETECTED)
    const mitmEvents = await SecurityLog.countDocuments({
      eventType: { $in: ['INVALID_SIGNATURE', 'REPLAY_DETECTED'] }
    });
    log(`\n🚨 MITM-Related Events (INVALID_SIGNATURE + REPLAY_DETECTED): ${mitmEvents}`, 
        mitmEvents > 0 ? colors.red + colors.bold : colors.green);
    
    // Key exchange events
    const keyExchangeEvents = await SecurityLog.countDocuments({
      eventType: { $in: ['KEY_EXCHANGE_ATTEMPT', 'KEY_EXCHANGE_SUCCESS', 'KEY_EXCHANGE_FAILURE'] }
    });
    log(`🔐 Key Exchange Events: ${keyExchangeEvents}`, colors.cyan);
    
    // Recent activity (last 24 hours)
    const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentLogs = await SecurityLog.countDocuments({
      timestamp: { $gte: last24Hours }
    });
    log(`\nRecent Activity (last 24 hours): ${recentLogs}`, colors.yellow);
    
    // Most recent log
    const mostRecent = await SecurityLog.findOne().sort({ timestamp: -1 });
    if (mostRecent) {
      log(`\nMost Recent Log:`, colors.cyan);
      log(`  Type: ${formatEventType(mostRecent.eventType)}`, colors.white);
      log(`  Time: ${formatTimestamp(mostRecent.timestamp)}`, colors.white);
    }
    
    // Recent INVALID_SIGNATURE events (MITM attempts)
    const recentInvalidSigs = await SecurityLog.countDocuments({
      eventType: 'INVALID_SIGNATURE',
      timestamp: { $gte: last24Hours }
    });
    if (recentInvalidSigs > 0) {
      log(`\n⚠️  Recent INVALID_SIGNATURE Events (last 24h): ${recentInvalidSigs}`, 
          colors.red + colors.bold);
    }
    
  } catch (error) {
    log(`Error getting summary: ${error.message}`, colors.red);
  }
}

// Main function to retrieve and display logs
async function retrieveLogs() {
  try {
    // Change to backend directory to use its node_modules
    const backendPath = join(__dirname, 'backend');
    process.chdir(backendPath);
    
    // Import models from backend
    const SecurityLogModule = await import(`file://${join(backendPath, 'models', 'SecurityLog.js')}`);
    const SecurityLog = SecurityLogModule.SecurityLog;
    
    // Connect to database (load .env from backend)
    dotenv.config({ path: join(backendPath, '.env') });
    const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/e2ee_messaging';
    
    logHeader('MITM Attack Verification - Security Logs Viewer');
    log(`Connecting to MongoDB...`, colors.cyan);
    
    const options = {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
    };

    if (MONGODB_URI.includes('mongodb+srv://')) {
      options.tls = true;
      options.tlsAllowInvalidCertificates = false;
    }

    await mongoose.connect(MONGODB_URI, options);
    log('✅ Connected to MongoDB successfully', colors.green);
    
    // Build query
    const query = {};
    
    if (options.eventType) {
      query.eventType = options.eventType;
    }
    
    // Date filtering
    if (options.hours) {
      const dateFrom = new Date(Date.now() - options.hours * 60 * 60 * 1000);
      query.timestamp = { $gte: dateFrom };
      log(`Filtering logs from last ${options.hours} hours...`, colors.cyan);
    }
    
    // Show summary if requested
    if (options.summary) {
      await getSummary(SecurityLog);
      await mongoose.connection.close();
      log('\n✅ Connection closed', colors.green);
      return;
    }
    
    // Get logs
    logSection('Security Logs');
    
    if (Object.keys(query).length > 0) {
      log(`Query: ${JSON.stringify(query, null, 2)}`, colors.blue);
    }
    
    const logs = await SecurityLog.find(query)
      .sort({ timestamp: -1 })
      .limit(options.limit)
      .populate('userId', 'username');
    
    const totalCount = await SecurityLog.countDocuments(query);
    
    log(`\nFound ${totalCount} log(s) matching criteria`, colors.green);
    log(`Displaying ${logs.length} log(s)`, colors.green);
    
    if (logs.length === 0) {
      log('\n⚠️  No logs found matching the criteria.', colors.yellow);
      log('This could mean:', colors.yellow);
      log('  1. No security events have occurred yet', colors.white);
      log('  2. The time filter is too restrictive', colors.white);
      log('  3. The system has not been tested with MITM attacks', colors.white);
      await getSummary(SecurityLog);
      await mongoose.connection.close();
      return;
    }
    
    // Group logs by type for better display
    const mitmLogs = logs.filter(log => 
      log.eventType === 'INVALID_SIGNATURE' || log.eventType === 'REPLAY_DETECTED'
    );
    const keyExchangeLogs = logs.filter(log => 
      log.eventType.startsWith('KEY_EXCHANGE')
    );
    const otherLogs = logs.filter(log => 
      !log.eventType.startsWith('KEY_EXCHANGE') && 
      log.eventType !== 'INVALID_SIGNATURE' && 
      log.eventType !== 'REPLAY_DETECTED'
    );
    
    // Display MITM-related logs first (most important)
    if (mitmLogs.length > 0) {
      logSubSection(`🚨 MITM-Related Events (${mitmLogs.length})`);
      log('These events indicate MITM attack detection:', colors.red + colors.bold);
      mitmLogs.forEach((logEntry, index) => {
        displayLog(logEntry, index, mitmLogs.length);
      });
    }
    
    // Display key exchange logs
    if (keyExchangeLogs.length > 0) {
      logSubSection(`🔐 Key Exchange Events (${keyExchangeLogs.length})`);
      keyExchangeLogs.forEach((logEntry, index) => {
        displayLog(logEntry, index, keyExchangeLogs.length);
      });
    }
    
    // Display other logs
    if (otherLogs.length > 0) {
      logSubSection(`Other Security Events (${otherLogs.length})`);
      otherLogs.forEach((logEntry, index) => {
        displayLog(logEntry, index, otherLogs.length);
      });
    }
    
    // Show summary at the end
    logSection('Quick Summary');
    const eventTypeCounts = {};
    logs.forEach(logEntry => {
      eventTypeCounts[logEntry.eventType] = (eventTypeCounts[logEntry.eventType] || 0) + 1;
    });
    
    Object.entries(eventTypeCounts).forEach(([type, count]) => {
      log(`${formatEventType(type)}: ${count}`, colors.white);
    });
    
    // Show full summary
    await getSummary(SecurityLog);
    
    // Verification message
    logSection('Verification Status');
    if (mitmLogs.length > 0) {
      log('✅ MITM Detection Confirmed!', colors.green + colors.bold);
      log(`   Found ${mitmLogs.length} MITM-related security event(s)`, colors.green);
      log('   Your system successfully detected and logged MITM attempts.', colors.green);
    } else {
      log('⚠️  No MITM events found in logs', colors.yellow);
      log('   This could mean:', colors.yellow);
      log('   - No MITM attacks have been attempted on your system', colors.white);
      log('   - The attack script is standalone and does not interact with your backend', colors.white);
      log('   - To test real MITM detection, you would need to perform an actual attack', colors.white);
      log('     against your running backend server', colors.white);
    }
    
    if (keyExchangeLogs.length > 0) {
      log(`\n✅ Key Exchange Activity Detected`, colors.green);
      log(`   Found ${keyExchangeLogs.length} key exchange event(s)`, colors.green);
      log('   This shows your system is actively performing key exchanges.', colors.green);
    }
    
    // Close connection
    await mongoose.connection.close();
    log('\n✅ Connection closed', colors.green);
    
  } catch (error) {
    log(`\n❌ Error: ${error.message}`, colors.red);
    console.error(error);
    if (mongoose.connection.readyState === 1) {
      await mongoose.connection.close();
    }
    process.exit(1);
  }
}

// Run the script
if (args.includes('--help') || args.includes('-h')) {
  showHelp();
} else {
  retrieveLogs();
}

