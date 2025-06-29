#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

const log = (message, color = 'reset') => {
  console.log(`${colors[color]}${message}${colors.reset}`);
};

// Configuration - ADJUST THESE PATHS FOR YOUR SETUP
const config = {
  // Frontend build directory
  sourceDir: path.join(__dirname, '..', 'build'),
  
  // Backend build directory - ADJUST THIS PATH!
  // Option 1: If backend is in a sibling directory
  targetDir: path.join(__dirname, '..', '..', 'backend', 'build'),
  
  // Option 2: If backend is in parent directory
  // targetDir: path.join(__dirname, '..', '..', 'sickoscoop-backend', 'build'),
  
  // Option 3: If you know the exact path
  // targetDir: '/path/to/your/backend/build',
};

// Utility functions
const ensureDirectoryExists = (dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    log(`📁 Created directory: ${dir}`, 'green');
  }
};

const copyFileSync = (src, dest) => {
  const destDir = path.dirname(dest);
  ensureDirectoryExists(destDir);
  fs.copyFileSync(src, dest);
};

const copyDirectoryRecursive = (src, dest) => {
  if (!fs.existsSync(src)) {
    log(`❌ Source directory does not exist: ${src}`, 'red');
    return false;
  }

  ensureDirectoryExists(dest);

  const items = fs.readdirSync(src);
  let filescopied = 0;

  for (const item of items) {
    const srcPath = path.join(src, item);
    const destPath = path.join(dest, item);
    const stat = fs.statSync(srcPath);

    if (stat.isDirectory()) {
      // Recursively copy subdirectories
      const subFilesCopied = copyDirectoryRecursive(srcPath, destPath);
      filescopied += subFilesCopied;
    } else {
      // Copy file
      copyFileSync(srcPath, destPath);
      filescopied++;
      
      // Log important files
      if (item.endsWith('.css') || item.endsWith('.js') || item.endsWith('.html')) {
        log(`  📄 ${item}`, 'cyan');
      }
    }
  }

  return filescopied;
};

const getDirectorySize = (dir) => {
  if (!fs.existsSync(dir)) return 0;
  
  let size = 0;
  const items = fs.readdirSync(dir);
  
  for (const item of items) {
    const itemPath = path.join(dir, item);
    const stat = fs.statSync(itemPath);
    
    if (stat.isDirectory()) {
      size += getDirectorySize(itemPath);
    } else {
      size += stat.size;
    }
  }
  
  return size;
};

const formatBytes = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

// Main copy function
const copyBuildToBackend = () => {
  log('\n🚀 SickoScoop Build Copy Script', 'bright');
  log('=====================================', 'blue');
  
  // Check if source build directory exists
  if (!fs.existsSync(config.sourceDir)) {
    log(`❌ Build directory not found: ${config.sourceDir}`, 'red');
    log('💡 Please run "npm run build" first to create the build directory.', 'yellow');
    process.exit(1);
  }

  // Remove existing target directory if it exists
  if (fs.existsSync(config.targetDir)) {
    log(`🗑️  Removing existing backend build directory...`, 'yellow');
    fs.rmSync(config.targetDir, { recursive: true, force: true });
  }

  log(`📂 Source: ${config.sourceDir}`, 'blue');
  log(`📂 Target: ${config.targetDir}`, 'blue');
  log('');

  // Copy files
  log('📋 Copying build files...', 'cyan');
  const startTime = Date.now();
  const filesCopied = copyDirectoryRecursive(config.sourceDir, config.targetDir);
  const endTime = Date.now();

  // Get size information
  const sourceSize = getDirectorySize(config.sourceDir);
  const targetSize = getDirectorySize(config.targetDir);

  log('');
  log('✅ Copy completed successfully!', 'green');
  log(`📊 Files copied: ${filesCopied}`, 'cyan');
  log(`📏 Total size: ${formatBytes(sourceSize)}`, 'cyan');
  log(`⏱️  Time taken: ${endTime - startTime}ms`, 'cyan');

  // Verify critical files
  log('');
  log('🔍 Verifying critical files...', 'yellow');
  
  const criticalFiles = [
    'index.html',
    'static/css',
    'static/js'
  ];

  let allFilesPresent = true;
  
  for (const file of criticalFiles) {
    const filePath = path.join(config.targetDir, file);
    if (fs.existsSync(filePath)) {
      log(`  ✅ ${file}`, 'green');
    } else {
      log(`  ❌ ${file}`, 'red');
      allFilesPresent = false;
    }
  }

  if (allFilesPresent) {
    log('');
    log('🎉 Build successfully copied to backend!', 'green');
    log('💡 Your backend will now serve the React app with all CSS and JS files.', 'cyan');
    log('🌐 No CORS issues - everything served from same origin!', 'cyan');
    log('');
    log('Next steps:', 'bright');
    log('1. Restart your backend server', 'yellow');
    log('2. Visit your backend URL (https://sickoscoop-backend-deo45.ondigitalocean.app/)', 'yellow');
    log('3. Your React app should load with proper styling!', 'yellow');
  } else {
    log('');
    log('⚠️  Some critical files are missing. Build may not work correctly.', 'red');
  }
};

// Handle command line arguments
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  log('\n📖 SickoScoop Build Copy Script', 'bright');
  log('================================', 'blue');
  log('');
  log('This script copies your React build to the backend directory.', 'cyan');
  log('');
  log('Usage:', 'bright');
  log('  node scripts/copy-build.js', 'yellow');
  log('  npm run copy-to-backend', 'yellow');
  log('  npm run build:frontend', 'yellow');
  log('');
  log('Options:', 'bright');
  log('  --help, -h    Show this help message', 'yellow');
  log('  --verbose, -v Verbose output', 'yellow');
  log('');
  process.exit(0);
}

// Run the copy process
try {
  copyBuildToBackend();
} catch (error) {
  log('');
  log('❌ Copy failed with error:', 'red');
  log(error.message, 'red');
  log('');
  log('💡 Troubleshooting tips:', 'yellow');
  log('1. Make sure you have built the React app first: npm run build', 'cyan');
  log('2. Check that the backend directory path is correct', 'cyan');
  log('3. Verify you have write permissions to the target directory', 'cyan');
  process.exit(1);
}