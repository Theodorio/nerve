#!/usr/bin/env node

const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const NERVE_API_URL = 'http://0.0.0.0:8000';

const client = new Client({
  authStrategy: new LocalAuth(),
  puppeteer: {
    headless: false,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  },
});

// 🔥 QR CODE
client.on('qr', (qr) => {
  console.log('Scan this QR:\n');
  qrcode.generate(qr, { small: true });
});

// ✅ READY
client.on('ready', () => {
  console.log('✅ WhatsApp bot is ready!');
});

// 🔥 MESSAGE HANDLER
client.on('message', async (message) => {
  if (message.fromMe) return;

  const sender = message.from.replace('@c.us', '');
  const text = message.body.trim();

  console.log(`[${sender}] ${text}`);

  try {
    const params = new URLSearchParams();
    params.append('sender', sender);
    params.append('message', text);

    const res = await fetch(`${NERVE_API_URL}/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
    });

    const data = await res.json();

    const reply = data.response || 'No response from backend';

    console.log(`[BOT → ${sender}] ${reply}`);

    await message.reply(reply);

  } catch (err) {
    console.error('Error:', err.message);
    await message.reply('⚠️ Server error');
  }
});

// 🚀 START
client.initialize();