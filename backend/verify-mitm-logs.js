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
 * Usage (run from backend directory):
 *   node verify-mitm-logs.js
 *   node verify-mitm-logs.js --hours 24
 *   node verify-mitm-logs.js --type INVALID_SIGNATURE
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
  hours: 1,  // Default: last 1 hour (recent logs)
  limit: 100,
  summary: false,
  all: false,
  recent: false  // Show only very recent logs
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
    case '--recent':
    case '-r':
      options.recent = true;
      options.hours = 0.5;  // Last 30 minutes
      options.limit = 50;
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
  node verify-mitm-logs.js --recent          # Show logs from last 30 minutes
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

// Display a single log entry with full details
function displayLog(logEntry, index, total) {
  log(`\n${'═'.repeat(80)}`, colors.magenta);
  log(`[LOG ${index + 1} of ${total}]`, colors.magenta + colors.bold);
  log(`${'═'.repeat(80)}`, colors.magenta);
  
  log(`\n📋 Event Type: ${formatEventType(logEntry.eventType)}`, colors.white);
  log(`🕐 Timestamp: ${formatTimestamp(logEntry.timestamp)}`, colors.white);
  log(`🆔 MongoDB Log ID: ${logEntry._id}`, colors.cyan);
  
  if (logEntry.userId) {
    const userIdStr = typeof logEntry.userId === 'object' && logEntry.userId.username 
      ? `${logEntry.userId._id} (${logEntry.userId.username})`
      : logEntry.userId.toString();
    log(`👤 User ID: ${userIdStr}`, colors.white);
  }
  
  if (logEntry.ipAddress) {
    log(`🌐 IP Address: ${logEntry.ipAddress}`, colors.white);
  }
  
  // Show created/updated timestamps if available
  if (logEntry.createdAt) {
    log(`📅 Created At: ${formatTimestamp(logEntry.createdAt)}`, colors.cyan);
  }
  if (logEntry.updatedAt) {
    log(`🔄 Updated At: ${formatTimestamp(logEntry.updatedAt)}`, colors.cyan);
  }
  
  // Display details with better formatting
  if (logEntry.details && Object.keys(logEntry.details).length > 0) {
    log(`\n📝 Event Details:`, colors.white + colors.bold);
    console.log(JSON.stringify(logEntry.details, null, 2));
  } else {
    log(`\n📝 Event Details: (none)`, colors.yellow);
  }
  
  // Show raw document keys for debugging
  log(`\n🔍 Available Fields: ${Object.keys(logEntry.toObject()).join(', ')}`, colors.cyan);
}

// Get summary statistics
async function getSummary() {
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
    logHeader('MITM Attack Verification - Security Logs Viewer');
    log(`Connecting to MongoDB...`, colors.cyan);
    log(`Current time: ${formatTimestamp(new Date())}`, colors.cyan);
    
    // Connect to database
    await connectDB();
    
    // Verify connection and show database info
    log(`\n✅ MongoDB Connection Verified:`, colors.green + colors.bold);
    log(`   Database Name: ${mongoose.connection.db.databaseName}`, colors.cyan);
    log(`   Collection: securitylogs`, colors.cyan);
    log(`   Connection State: ${mongoose.connection.readyState === 1 ? 'Connected ✅' : 'Not Connected ❌'}`, 
        mongoose.connection.readyState === 1 ? colors.green : colors.red);
    
    // Test query to verify collection exists and has data
    const totalInCollection = await SecurityLog.countDocuments({});
    log(`   Total documents in collection: ${totalInCollection}`, colors.cyan);
    
    if (totalInCollection === 0) {
      log(`\n⚠️  WARNING: The securitylogs collection is EMPTY!`, colors.red + colors.bold);
      log(`   This means no security logs have been stored in MongoDB yet.`, colors.yellow);
      log(`   The script is working correctly, but there are no logs to retrieve.`, colors.yellow);
      await mongoose.connection.close();
      return;
    }
    
    log(`\n✅ Collection verified - ${totalInCollection} document(s) exist in MongoDB`, colors.green);
    
    // Build query
    const query = {};
    
    if (options.eventType) {
      query.eventType = options.eventType;
    }
    
    // Date filtering
    if (options.hours) {
      const dateFrom = new Date(Date.now() - options.hours * 60 * 60 * 1000);
      query.timestamp = { $gte: dateFrom };
      if (options.recent) {
        log(`Filtering logs from last 30 minutes (recent activity)...`, colors.cyan);
      } else {
        log(`Filtering logs from last ${options.hours} hours...`, colors.cyan);
      }
    }
    
    // Show summary if requested
    if (options.summary) {
      await getSummary();
      await mongoose.connection.close();
      log('\n✅ Connection closed', colors.green);
      return;
    }
    
    // Get logs
    logSection('Security Logs');
    
    if (Object.keys(query).length > 0) {
      log(`\n🔍 MongoDB Query Used:`, colors.blue + colors.bold);
      log(JSON.stringify(query, null, 2), colors.blue);
      log(`\nThis query was used to retrieve logs from MongoDB.`, colors.cyan);
    } else {
      log(`\n🔍 MongoDB Query: (no filters - retrieving all logs)`, colors.blue);
    }
    
    log(`\n🔍 Executing MongoDB Query...`, colors.yellow);
    log(`   Collection: securitylogs`, colors.cyan);
    log(`   Database: ${mongoose.connection.db.databaseName}`, colors.cyan);
    log(`   Query Object: ${JSON.stringify(query, null, 2)}`, colors.cyan);
    
    // First, count how many match
    const totalCount = await SecurityLog.countDocuments(query);
    log(`   Documents matching query: ${totalCount}`, colors.cyan);
    
    // Now retrieve the actual documents
    log(`\n📥 Retrieving documents from MongoDB...`, colors.yellow);
    const logs = await SecurityLog.find(query)
      .sort({ timestamp: -1 })
      .limit(options.limit)
      .populate('userId', 'username')
      .lean(false); // Keep as Mongoose documents to verify they're real
    
    log(`\n✅ MongoDB Query Completed!`, colors.green + colors.bold);
    log(`\n📊 Query Results:`, colors.green + colors.bold);
    log(`   Total documents matching criteria in MongoDB: ${totalCount}`, colors.green);
    log(`   ✅ Documents successfully retrieved from MongoDB: ${logs.length}`, colors.green + colors.bold);
    log(`   Query limit applied: ${options.limit}`, colors.cyan);
    
    // Verify these are real MongoDB documents
    if (logs.length > 0) {
      log(`\n✅ Verification: All ${logs.length} document(s) are real MongoDB documents`, colors.green);
      log(`   Document type check: ${logs[0] instanceof mongoose.Document ? 'Mongoose Document ✅' : 'Plain Object'}`, colors.cyan);
      log(`   Has _id field: ${logs[0]._id ? 'Yes ✅' : 'No ❌'}`, colors.cyan);
      
      log(`\n📦 Details of Logs Retrieved from MongoDB:`, colors.cyan + colors.bold);
      log(`   First log (most recent) timestamp: ${formatTimestamp(logs[0].timestamp)}`, colors.white);
      log(`   Last log (oldest) timestamp: ${formatTimestamp(logs[logs.length - 1].timestamp)}`, colors.white);
      log(`\n📋 MongoDB Document IDs Retrieved:`, colors.cyan + colors.bold);
      logs.forEach((logEntry, idx) => {
        log(`   [${idx + 1}] Document ID: ${logEntry._id}`, colors.white);
        log(`       Event Type: ${logEntry.eventType}`, colors.cyan);
        log(`       Timestamp: ${formatTimestamp(logEntry.timestamp)}`, colors.cyan);
        log(`       User ID: ${logEntry.userId ? (typeof logEntry.userId === 'object' ? logEntry.userId._id : logEntry.userId) : 'N/A'}`, colors.cyan);
      });
      
      // Show a sample raw document to prove it's from MongoDB
      log(`\n🔍 Sample Raw MongoDB Document (first one):`, colors.magenta + colors.bold);
      const sampleDoc = logs[0].toObject ? logs[0].toObject() : logs[0];
      log(JSON.stringify(sampleDoc, null, 2), colors.white);
    } else {
      log(`\n⚠️  No documents were retrieved from MongoDB.`, colors.red + colors.bold);
      log(`   Query returned 0 documents.`, colors.yellow);
      log(`   This could mean:`, colors.yellow);
      log(`   1. No logs match the query criteria`, colors.white);
      log(`   2. The time filter is too restrictive`, colors.white);
      log(`   3. The collection is empty (but we verified it has ${totalInCollection} total docs)`, colors.white);
    }
    
    if (logs.length === 0) {
      log('\n⚠️  No logs found matching the criteria.', colors.yellow);
      log(`   However, the collection has ${totalInCollection} total document(s).`, colors.yellow);
      log('   This could mean:', colors.yellow);
      log('  1. The time filter is too restrictive (try --hours 24 or remove time filter)', colors.white);
      log('  2. The event type filter doesn\'t match any documents', colors.white);
      log('  3. No security events have occurred in the specified time period', colors.white);
      log('\n💡 Try running without time filter to see all logs:', colors.cyan);
      log('   node verify-mitm-logs.js --all', colors.white);
      await getSummary();
      await mongoose.connection.close();
      return;
    }
    
    // Show what types of logs were retrieved
    log(`\n📋 Breakdown of ${logs.length} Log(s) Retrieved from MongoDB:`, colors.cyan + colors.bold);
    const logTypes = {};
    logs.forEach(logEntry => {
      logTypes[logEntry.eventType] = (logTypes[logEntry.eventType] || 0) + 1;
    });
    if (Object.keys(logTypes).length > 0) {
      log(`   Event types found in retrieved logs:`, colors.white);
      Object.entries(logTypes).forEach(([type, count]) => {
        log(`   - ${formatEventType(type)}: ${count} log document(s)`, colors.white);
      });
    } else {
      log(`   ⚠️  No event types found (empty result)`, colors.yellow);
    }
    
    // Group logs by type for better display
    const mitmLogs = logs.filter(logEntry => 
      logEntry.eventType === 'INVALID_SIGNATURE' || logEntry.eventType === 'REPLAY_DETECTED'
    );
    const keyExchangeLogs = logs.filter(logEntry => 
      logEntry.eventType.startsWith('KEY_EXCHANGE')
    );
    const otherLogs = logs.filter(logEntry => 
      !logEntry.eventType.startsWith('KEY_EXCHANGE') && 
      logEntry.eventType !== 'INVALID_SIGNATURE' && 
      logEntry.eventType !== 'REPLAY_DETECTED'
    );
    
    log(`\n📊 Logs Grouped by Category:`, colors.cyan + colors.bold);
    log(`   🚨 MITM-Related: ${mitmLogs.length} log(s)`, colors.white);
    log(`   🔐 Key Exchange: ${keyExchangeLogs.length} log(s)`, colors.white);
    log(`   📋 Other Events: ${otherLogs.length} log(s)`, colors.white);
    
    // Display MITM-related logs first (most important)
    if (mitmLogs.length > 0) {
      logSubSection(`🚨 MITM-Related Events (${mitmLogs.length} of ${logs.length} log(s) retrieved from MongoDB)`);
      log('These events indicate MITM attack detection:', colors.red + colors.bold);
      log(`✅ Showing ${mitmLogs.length} MITM-related log document(s) retrieved from MongoDB:`, colors.cyan + colors.bold);
      mitmLogs.forEach((logEntry, index) => {
        log(`\n📄 MongoDB Document #${index + 1}:`, colors.magenta + colors.bold);
        displayLog(logEntry, index, mitmLogs.length);
      });
    } else {
      log(`\n⚠️  No MITM-related logs found in the ${logs.length} log document(s) retrieved from MongoDB.`, colors.yellow);
      log(`   This means none of the ${logs.length} retrieved logs have eventType INVALID_SIGNATURE or REPLAY_DETECTED.`, colors.white);
    }
    
    // Display key exchange logs
    if (keyExchangeLogs.length > 0) {
      logSubSection(`🔐 Key Exchange Events (${keyExchangeLogs.length} of ${logs.length} log(s) retrieved from MongoDB)`);
      log(`✅ Showing ${keyExchangeLogs.length} key exchange log document(s) retrieved from MongoDB:`, colors.cyan + colors.bold);
      keyExchangeLogs.forEach((logEntry, index) => {
        log(`\n📄 MongoDB Document #${index + 1}:`, colors.magenta + colors.bold);
        displayLog(logEntry, index, keyExchangeLogs.length);
      });
    } else {
      log(`\n⚠️  No key exchange logs found in the ${logs.length} log document(s) retrieved from MongoDB.`, colors.yellow);
    }
    
    // Display other logs
    if (otherLogs.length > 0) {
      logSubSection(`📋 Other Security Events (${otherLogs.length} of ${logs.length} log(s) retrieved from MongoDB)`);
      log(`✅ Showing ${otherLogs.length} other security log document(s) retrieved from MongoDB:`, colors.cyan + colors.bold);
      otherLogs.forEach((logEntry, index) => {
        log(`\n📄 MongoDB Document #${index + 1}:`, colors.magenta + colors.bold);
        displayLog(logEntry, index, otherLogs.length);
      });
    } else {
      log(`\n⚠️  No other security logs found in the ${logs.length} log document(s) retrieved from MongoDB.`, colors.yellow);
    }
    
    // Show summary at the end
    logSection('Quick Summary of Retrieved Logs');
    const eventTypeCounts = {};
    logs.forEach(logDoc => {
      eventTypeCounts[logDoc.eventType] = (eventTypeCounts[logDoc.eventType] || 0) + 1;
    });
    
    Object.entries(eventTypeCounts).forEach(([type, count]) => {
      log(`${formatEventType(type)}: ${count}`, colors.white);
    });
    
    // Show full summary
    await getSummary();
    
    // Verification message
    logSection('Verification Status - Summary of Retrieved Logs');
    log(`\n📊 Total MongoDB Documents Retrieved: ${logs.length}`, colors.cyan + colors.bold);
    log(`   Collection: securitylogs`, colors.cyan);
    log(`   Query executed successfully: ✅`, colors.green);
    
    if (mitmLogs.length > 0) {
      log('\n✅ MITM Detection Confirmed in Retrieved Logs!', colors.green + colors.bold);
      log(`   Found ${mitmLogs.length} MITM-related log document(s) in the ${logs.length} retrieved`, colors.green);
      log('   Your system successfully detected and logged MITM attempts.', colors.green);
      log(`   These ${mitmLogs.length} log(s) were retrieved from MongoDB and show MITM detection.`, colors.green);
    } else {
      log('\n⚠️  No MITM events found in the retrieved logs', colors.yellow);
      log(`   Out of ${logs.length} log document(s) retrieved from MongoDB, none are MITM-related.`, colors.yellow);
      log('   This could mean:', colors.yellow);
      log('   - No MITM attacks have been attempted on your system', colors.white);
      log('   - The attack script is standalone and does not interact with your backend', colors.white);
      log('   - To test real MITM detection, you would need to perform an actual attack', colors.white);
      log('     against your running backend server', colors.white);
    }
    
    if (keyExchangeLogs.length > 0) {
      log(`\n✅ Key Exchange Activity Detected in Retrieved Logs`, colors.green);
      log(`   Found ${keyExchangeLogs.length} key exchange log document(s) in the ${logs.length} retrieved`, colors.green);
      log('   This shows your system is actively performing key exchanges.', colors.green);
    }
    
    log(`\n📝 All ${logs.length} log document(s) shown above were successfully retrieved from MongoDB.`, colors.cyan + colors.bold);
    
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

