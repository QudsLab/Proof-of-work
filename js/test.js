#!/usr/bin/env node
/**
 * Minimal WebAssembly Test for Proof-of-Work Binaries
 * Verifies WASM files exist and are loadable
 */

const fs = require('fs');
const path = require('path');

function testWasm() {
  console.log('\n=== WASM Binary Test ===\n');

  const wasmDir = path.join(__dirname, '..', 'bin', 'wasm', 'js');
  const files = [
    'client.js',
    'client.wasm',
    'server.js',
    'server.wasm'
  ];

  let allPass = true;

  // Check file existence and sizes
  files.forEach(filename => {
    const filepath = path.join(wasmDir, filename);
    if (fs.existsSync(filepath)) {
      const stats = fs.statSync(filepath);
      const sizeMB = (stats.size / 1024 / 1024).toFixed(2);
      console.log(`[OK] ${filename.padEnd(15)} (${sizeMB} MB)`);
    } else {
      console.log(`[FAIL] ${filename} - NOT FOUND`);
      allPass = false;
    }
  });

  if (!allPass) {
    console.log('\n[FAIL] Some WASM files are missing\n');
    process.exit(1);
  }

  // Basic module loading test
  try {
    const clientPath = path.join(wasmDir, 'client.js');
    const serverPath = path.join(wasmDir, 'server.js');
    
    // Just verify they can be required (syntax check)
    require(clientPath);
    console.log('[OK] client.js loads successfully');
    
    require(serverPath);
    console.log('[OK] server.js loads successfully');
    
    console.log('\n[PASS] All WASM tests passed\n');
    process.exit(0);
  } catch (error) {
    console.log(`\n[FAIL] Module loading error: ${error.message}\n`);
    process.exit(1);
  }
}

testWasm();
