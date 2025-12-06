#!/usr/bin/env node
/**
 * WebAssembly Test for Proof-of-Work Binaries
 * Tests both client and server WASM modules
 */

const fs = require('fs');
const path = require('path');

async function testWasm() {
  console.log('🧪 Testing WebAssembly binaries...\n');

  const clientJsPath = path.join(__dirname, '..', 'bin', 'wasm', 'js', 'client.js');
  const clientWasmPath = path.join(__dirname, '..', 'bin', 'wasm', 'js', 'client.wasm');
  const serverJsPath = path.join(__dirname, '..', 'bin', 'wasm', 'js', 'server.js');
  const serverWasmPath = path.join(__dirname, '..', 'bin', 'wasm', 'js', 'server.wasm');

  // Check if files exist
  const files = [
    { path: clientJsPath, name: 'client.js' },
    { path: clientWasmPath, name: 'client.wasm' },
    { path: serverJsPath, name: 'server.js' },
    { path: serverWasmPath, name: 'server.wasm' }
  ];

  let allExist = true;
  for (const file of files) {
    if (fs.existsSync(file.path)) {
      const stats = fs.statSync(file.path);
      console.log(`✓ ${file.name} exists (${stats.size} bytes)`);
    } else {
      console.log(`✗ ${file.name} NOT FOUND`);
      allExist = false;
    }
  }

  if (!allExist) {
    console.error('\n❌ Some WASM files are missing!');
    process.exit(1);
  }

  console.log('\n✓ All WASM files present');
  
  // Try to load the modules (basic smoke test)
  try {
    console.log('\n🔍 Loading client module...');
    const ClientModule = require(clientJsPath);
    console.log('✓ Client module loaded');

    console.log('\n🔍 Loading server module...');
    const ServerModule = require(serverJsPath);
    console.log('✓ Server module loaded');

    console.log('\n✅ WASM test passed!');
    process.exit(0);
  } catch (error) {
    console.error('\n❌ Error loading WASM modules:', error.message);
    process.exit(1);
  }
}

testWasm().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
