#!/bin/bash

echo "=== 1. Get Server Public Key ==="
curl -s http://localhost:9001/api/public-key > /tmp/pubkey.json
cat /tmp/pubkey.json | python3 -m json.tool 2>/dev/null | head -8
echo "..."

echo ""
echo "=== 2. Encrypt Data ==="
# Extract just the publicKey object and use it in the encrypt request
node -e "
const pubkey = require('/tmp/pubkey.json').publicKey;
const data = { data: 'Hello Secret World!', recipientPublicKey: pubkey };
require('http').request({
  hostname: 'localhost',
  port: 9001,
  path: '/api/encrypt',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
}, res => {
  let body = '';
  res.on('data', c => body += c);
  res.on('end', () => {
    console.log(body);
    require('fs').writeFileSync('/tmp/encrypted.json', body);
  });
}).end(JSON.stringify(data));
"

echo ""
echo "=== 3. Decrypt Data ==="
curl -s -X POST http://localhost:9001/api/decrypt \
  -H "Content-Type: application/json" \
  -d @/tmp/encrypted.json | python3 -m json.tool 2>/dev/null
