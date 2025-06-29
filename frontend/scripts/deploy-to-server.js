#!/usr/bin/env node

const { execSync } = require('child_process');
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
  cyan: '\x1b[36m'
};

const log = (message, color = 'reset') => {
  console.log(`${colors[color]}${message}${colors.reset}`);
};

// Configuration - UPDATE THESE FOR YOUR SERVER
const config = {
  // Your DigitalOcean droplet details
  serverHost: 'sickoscoop-backend-deo45.ondigitalocean.app',
  serverUser: 'root', // or your server username
  serverPath: '/var/www/sickoscoop-backend', // path to your backend on server
  
  // Local paths
  buildDir: path.join(__dirname, '..', 'build'),
  backendLocalDir: path.join(__dirname, '..', '..', 'backend'), // adjust as needed
  
  // SSH key path (if using key authentication)
  sshKeyPath: '~/.ssh/id_rsa', // adjust to your SSH key path
  
  // Server commands
  serverRestartCommand: 'pm2 restart sickoscoop-backend || npm restart', // adjust as needed
};

// Deployment methods
const deploymentMethods = {
  // Method 1: SCP (Secure Copy) - Most common
  scp: () => {
    log('🚀 Deploying via SCP...', 'cyan');
    
    const scpCommand = `scp -r ${config.buildDir}/* ${config.serverUser}@${config.serverHost}:${config.serverPath}/build/`;
    
    log(`📤 Executing: ${scpCommand}`, 'blue');
    try {
      execSync(scpCommand, { stdio: 'inherit' });
      log('✅ SCP upload completed!', 'green');
      return true;
    } catch (error) {
      log('❌ SCP upload failed:', 'red');
      log(error.message, 'red');
      return false;
    }
  },

  // Method 2: rsync - More efficient for incremental updates
  rsync: () => {
    log('🚀 Deploying via rsync...', 'cyan');
    
    const rsyncCommand = `rsync -avz --delete ${config.buildDir}/ ${config.serverUser}@${config.serverHost}:${config.serverPath}/build/`;
    
    log(`📤 Executing: ${rsyncCommand}`, 'blue');
    try {
      execSync(rsyncCommand, { stdio: 'inherit' });
      log('✅ rsync upload completed!', 'green');
      return true;
    } catch (error) {
      log('❌ rsync upload failed:', 'red');
      log(error.message, 'red');
      return false;
    }
  },

  // Method 3: Git-based deployment
  git: () => {
    log('🚀 Deploying via Git...', 'cyan');
    
    try {
      // Add build files to git
      log('📋 Adding build files to git...', 'blue');
      execSync('git add build/', { stdio: 'inherit' });
      
      // Commit build files
      const commitMessage = `Deploy: ${new Date().toISOString()}`;
      execSync(`git commit -m "${commitMessage}"`, { stdio: 'inherit' });
      
      // Push to server
      log('📤 Pushing to server...', 'blue');
      execSync('git push origin main', { stdio: 'inherit' }); // adjust branch as needed
      
      log('✅ Git deployment completed!', 'green');
      return true;
    } catch (error) {
      log('❌ Git deployment failed:', 'red');
      log(error.message, 'red');
      return false;
    }
  },

  // Method 4: Manual instructions
  manual: () => {
    log('📋 Manual Deployment Instructions:', 'cyan');
    log('', 'reset');
    log('1. Copy your build folder to your server:', 'yellow');
    log(`   scp -r build/* ${config.serverUser}@${config.serverHost}:${config.serverPath}/build/`, 'cyan');
    log('', 'reset');
    log('2. SSH into your server:', 'yellow');
    log(`   ssh ${config.serverUser}@${config.serverHost}`, 'cyan');
    log('', 'reset');
    log('3. Navigate to your backend directory:', 'yellow');
    log(`   cd ${config.serverPath}`, 'cyan');
    log('', 'reset');
    log('4. Restart your backend service:', 'yellow');
    log(`   ${config.serverRestartCommand}`, 'cyan');
    log('', 'reset');
    log('5. Test your deployment:', 'yellow');
    log(`   curl ${config.serverHost}/api/health`, 'cyan');
    log(`   Visit: https://${config.serverHost}`, 'cyan');
    
    return true;
  }
};

// Pre-deployment checks
const preDeploymentChecks = () => {
  log('🔍 Running pre-deployment checks...', 'yellow');
  
  // Check if build directory exists
  if (!fs.existsSync(config.buildDir)) {
    log('❌ Build directory not found. Please run "npm run build" first.', 'red');
    return false;
  }
  
  // Check if index.html exists
  const indexPath = path.join(config.buildDir, 'index.html');
  if (!fs.existsSync(indexPath)) {
    log('❌ index.html not found in build directory.', 'red');
    return false;
  }
  
  // Check if CSS files exist
  const staticCssPath = path.join(config.buildDir, 'static', 'css');
  if (!fs.existsSync(staticCssPath)) {
    log('⚠️  CSS directory not found. CSS might not load properly.', 'yellow');
  } else {
    log('✅ CSS files found', 'green');
  }
  
  // Check if JS files exist
  const staticJsPath = path.join(config.buildDir, 'static', 'js');
  if (!fs.existsSync(staticJsPath)) {
    log('⚠️  JS directory not found. JavaScript might not load properly.', 'yellow');
  } else {
    log('✅ JavaScript files found', 'green');
  }
  
  log('✅ Pre-deployment checks completed', 'green');
  return true;
};

// Restart server
const restartServer = () => {
  log('🔄 Restarting server...', 'cyan');
  
  const sshCommand = `ssh ${config.serverUser}@${config.serverHost} "cd ${config.serverPath} && ${config.serverRestartCommand}"`;
  
  try {
    execSync(sshCommand, { stdio: 'inherit' });
    log('✅ Server restarted successfully!', 'green');
    return true;
  } catch (error) {
    log('❌ Server restart failed:', 'red');
    log('💡 You may need to restart the server manually:', 'yellow');
    log(`   ssh ${config.serverUser}@${config.serverHost}`, 'cyan');
    log(`   cd ${config.serverPath}`, 'cyan');
    log(`   ${config.serverRestartCommand}`, 'cyan');
    return false;
  }
};

// Test deployment
const testDeployment = () => {
  log('🧪 Testing deployment...', 'cyan');
  
  try {
    // Test API health endpoint
    const healthCommand = `curl -s ${config.serverHost}/api/health`;
    const healthResponse = execSync(healthCommand, { encoding: 'utf8' });
    
    if (healthResponse.includes('OK') || healthResponse.includes('running')) {
      log('✅ API is responding', 'green');
    } else {
      log('⚠️  API response unclear:', 'yellow');
      log(healthResponse, 'cyan');
    }
    
    // Test static file serving
    const staticCommand = `curl -s -o /dev/null -w "%{http_code}" ${config.serverHost}/`;
    const staticResponse = execSync(staticCommand, { encoding: 'utf8' });
    
    if (staticResponse === '200') {
      log('✅ Static files are being served', 'green');
    } else {
      log(`⚠️  Static file response: ${staticResponse}`, 'yellow');
    }
    
    log('', 'reset');
    log('🌐 Test your deployment:', 'bright');
    log(`   https://${config.serverHost}`, 'cyan');
    log(`   https://${config.serverHost}/api/health`, 'cyan');
    
  } catch (error) {
    log('⚠️  Testing failed (this might be normal):', 'yellow');
    log('💡 Please test manually in your browser', 'cyan');
  }
};

// Main deployment function
const deploy = (method = 'manual') => {
  log('\n🚀 SickoScoop Deployment Script', 'bright');
  log('==================================', 'blue');
  log(`📊 Method: ${method}`, 'cyan');
  log(`🌐 Target: ${config.serverHost}`, 'cyan');
  log('', 'reset');
  
  // Run pre-deployment checks
  if (!preDeploymentChecks()) {
    log('❌ Pre-deployment checks failed. Aborting.', 'red');
    process.exit(1);
  }
  
  // Execute deployment
  const deploymentFunction = deploymentMethods[method];
  if (!deploymentFunction) {
    log(`❌ Unknown deployment method: ${method}`, 'red');
    log('💡 Available methods: scp, rsync, git, manual', 'yellow');
    process.exit(1);
  }
  
  const deploymentSuccess = deploymentFunction();
  
  if (deploymentSuccess && method !== 'manual') {
    // Restart server if deployment succeeded
    restartServer();
    
    // Test deployment
    setTimeout(() => {
      testDeployment();
    }, 3000); // Wait 3 seconds for server to restart
  }
  
  log('', 'reset');
  log('🎉 Deployment process completed!', 'green');
};

// Command line interface
const method = process.argv[2] || 'manual';

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  log('\n📖 SickoScoop Deployment Script', 'bright');
  log('=================================', 'blue');
  log('', 'reset');
  log('This script deploys your React build to your DigitalOcean server.', 'cyan');
  log('', 'reset');
  log('Usage:', 'bright');
  log('  node scripts/deploy-to-server.js [method]', 'yellow');
  log('  npm run deploy', 'yellow');
  log('', 'reset');
  log('Methods:', 'bright');
  log('  scp     - Deploy using SCP (Secure Copy)', 'yellow');
  log('  rsync   - Deploy using rsync (incremental)', 'yellow');
  log('  git     - Deploy using Git push', 'yellow');
  log('  manual  - Show manual deployment instructions (default)', 'yellow');
  log('', 'reset');
  log('Examples:', 'bright');
  log('  node scripts/deploy-to-server.js scp', 'cyan');
  log('  node scripts/deploy-to-server.js rsync', 'cyan');
  log('  node scripts/deploy-to-server.js manual', 'cyan');
  log('', 'reset');
  process.exit(0);
}

// Run deployment
deploy(method);