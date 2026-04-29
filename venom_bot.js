#!/usr/bin/env node

/**
 * Venom JS WhatsApp Bot integration with Nerve
 */

const venom = require('venom-bot');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

function loadDotEnv() {
  const dotenvPath = path.join(process.cwd(), '.env');

  if (!fs.existsSync(dotenvPath)) {
    return;
  }

  const content = fs.readFileSync(dotenvPath, 'utf8');

  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) {
      continue;
    }

    const separatorIndex = trimmed.indexOf('=');
    const key = trimmed.slice(0, separatorIndex).trim();
    if (!key || Object.prototype.hasOwnProperty.call(process.env, key)) {
      continue;
    }

    let value = trimmed.slice(separatorIndex + 1).trim();
    if (value.length >= 2 && value[0] === value[value.length - 1] && (value[0] === '"' || value[0] === "'")) {
      value = value.slice(1, -1);
    }

    process.env[key] = value;
  }
}

loadDotEnv();

const NERVE_API_URL = process.env.NERVE_API_URL || 'http://localhost:8000';
const WS_URL = NERVE_API_URL.replace('http', 'ws').replace('https', 'wss');

let client;
const connections = new Map(); // Map sender -> { ws, pendingRequests, connected, openPromise }

/**
 * Connect to Nerve backend via WebSocket for a specific sender.
 */
function connectToNerve(sender) {
  const existing = connections.get(sender);
  if (existing?.ws && existing.ws.readyState === WebSocket.OPEN) {
    return Promise.resolve(existing.ws);
  }

  if (existing?.openPromise) {
    return existing.openPromise;
  }

  const connection = existing || {
    ws: null,
    pendingRequests: new Map(),
    connected: false,
    openPromise: null,
  };

  connection.openPromise = new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WS_URL}/ws/whatsapp/${encodeURIComponent(sender)}`);
    connection.ws = ws;

    ws.on('open', () => {
      connection.connected = true;
      console.log(`[${sender}] Connected to Nerve backend`);
      connection.openPromise = null;
      connections.set(sender, connection);
      resolve(ws);
    });

    ws.on('error', (err) => {
      console.error(`[${sender}] WebSocket error:`, err.message);
      if (!connection.connected) {
        reject(err);
      }
      for (const pending of connection.pendingRequests.values()) {
        clearTimeout(pending.timeout);
        pending.reject(err);
      }
      connection.pendingRequests.clear();
      connections.delete(sender);
    });

    ws.on('message', (data) => {
      handleServerMessage(sender, data).catch((err) => {
        console.error(`[${sender}] Failed to handle backend message:`, err.message);
      });
    });

    ws.on('close', () => {
      console.log(`[${sender}] Disconnected from Nerve backend`);
      connection.connected = false;
      connection.openPromise = null;
      for (const pending of connection.pendingRequests.values()) {
        clearTimeout(pending.timeout);
        pending.reject(new Error('Nerve connection closed'));
      }
      connection.pendingRequests.clear();
      connections.delete(sender);
    });
  });

  connections.set(sender, connection);
  return connection.openPromise;
}

/**
 * Forward backend progress messages to WhatsApp.
 */
async function handleServerMessage(sender, data) {
  const connection = connections.get(sender);
  if (!connection) {
    return;
  }

  let payload;
  try {
    payload = JSON.parse(data);
  } catch (err) {
    console.error(`[${sender}] Invalid JSON from Nerve:`, data.toString());
    return;
  }

  if (payload.status === 'progress' || payload.event === 'progress') {
    const text = payload.response || payload.message;
    if (text && client) {
      await client.sendText(sender, text);
    }
    return;
  }

  const requestId = payload.request_id;
  if (!requestId || !connection.pendingRequests.has(requestId)) {
    console.log(`[${sender}] Unmatched backend message:`, payload);
    return;
  }

  const pending = connection.pendingRequests.get(requestId);
  clearTimeout(pending.timeout);
  connection.pendingRequests.delete(requestId);
  pending.resolve(payload);
}

/**
 * Send a message to Nerve and get response.
 */
async function sendToNerve(sender, message) {
  try {
    const ws = await connectToNerve(sender);
    const connection = connections.get(sender);
    const requestId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        if (connection) {
          connection.pendingRequests.delete(requestId);
        }
        reject(new Error('Nerve response timeout'));
      }, 30000);

      if (!connection) {
        clearTimeout(timeout);
        reject(new Error('Connection not available'));
        return;
      }

      connection.pendingRequests.set(requestId, { resolve, reject, timeout });
      ws.send(JSON.stringify({ message, request_id: requestId }));
    });
  } catch (err) {
    console.error(`[${sender}] Error sending to Nerve:`, err.message);
    return {
      status: 'error',
      response: `Failed to reach Nerve backend: ${err.message}`
    };
  }
}

/**
 * Fallback HTTP method if WebSocket fails.
 */
async function sendToNerveHTTP(sender, message) {
  try {
    const response = await fetch(`${NERVE_API_URL}/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ sender, message })
    });
    return await response.json();
  } catch (err) {
    console.error(`[${sender}] HTTP error:`, err.message);
    return {
      status: 'error',
      response: 'Failed to reach Nerve backend'
    };
  }
}

async function sendResponseToWhatsApp(target, result) {
  const response = result.response || 'No response from Nerve';
  console.log(`[${target}] Sending: ${response}`);
  await client.sendText(target, response);

  const extraParts = Array.isArray(result.response_parts) ? result.response_parts : [];
  for (const part of extraParts) {
    const chunk = String(part || '').trim();
    if (!chunk) {
      continue;
    }
    await client.sendText(target, chunk);
  }
}

async function handleIncomingMessage(message) {
  if (message.isGroupMsg || message.fromMe) {
    return;
  }

  const sender = message.from;
  const body = message.body?.trim();

  if (!body) {
    return;
  }

  console.log(`[${sender}] Received: ${body}`);

  try {
    let result = await sendToNerve(sender, body);

    if (result.status === 'error') {
      console.log(`[${sender}] WS failed, trying HTTP fallback...`);
      result = await sendToNerveHTTP(sender, body);
    }

    await sendResponseToWhatsApp(sender, result);
  } catch (err) {
    console.error(`[${sender}] Error:`, err.message);
    if (client) {
      await client.sendText(sender, `Error: ${err.message}`);
    }
  }
}

/**
 * Main Venom Initialization (FIXED QR HANDLING)
 */
venom
  .create(
    'nerve-bot',

    // ✅ QR CODE HANDLER (FIX)
    (base64Qr, asciiQR) => {
      console.log('\nScan this QR code:\n');
      console.log(asciiQR);
    },

    // ✅ SESSION STATUS
    (statusSession) => {
      console.log('Status:', statusSession);
    },

    // ✅ OPTIONS
    {
  headless: false,
  useChrome: true,
  browserArgs: ['--no-sandbox', '--disable-setuid-sandbox'],
}
  )
  .then((whatsappClient) => {
    client = whatsappClient;
    console.log('✓ Venom Bot connected to WhatsApp');

    // Listen for incoming messages
    client.onMessage(handleIncomingMessage);
    // Optional: state logs
    client.onStateChange((state) => {
      console.log(`WhatsApp state: ${state}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize Venom Bot:', err);
    process.exit(1);
  });

/**
 * Graceful shutdown
 */
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  if (client) client.close();
  connections.forEach((connection) => {
    if (connection?.ws) {
      connection.ws.close();
    }
    if (connection?.pendingRequests) {
      for (const pending of connection.pendingRequests.values()) {
        clearTimeout(pending.timeout);
        pending.reject(new Error('Shutting down'));
      }
      connection.pendingRequests.clear();
    }
  });
  process.exit(0);
});