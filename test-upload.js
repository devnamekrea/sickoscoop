// test-upload.js - Complete Upload Test Script
// Copy this entire code into your test-upload.js file

const fetch = require('node-fetch');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

// Configuration
const SERVER_URL = process.env.SERVER_URL || 'http://localhost:3001';
const TEST_EMAIL = 'demo@sickoscoop.com';
const TEST_PASSWORD = 'demo';

console.log('🧪 SickoScoop Upload Test Script');
console.log('================================');
console.log('🌐 Testing server:', SERVER_URL);

async function testServer() {
  console.log('\n1️⃣ Testing server connection...');
  
  try {
    const response = await fetch(`${SERVER_URL}/api/health`);
    const data = await response.json();
    
    if (response.ok) {
      console.log('✅ Server is running:', data.message);
      return true;
    } else {
      console.log('❌ Server returned error:', data);
      return false;
    }
  } catch (error) {
    console.log('❌ Server connection failed:', error.message);
    console.log('💡 Make sure your server is running on', SERVER_URL);
    console.log('💡 Start server with: node enhanced-server.js');
    return false;
  }
}

async function testLogin() {
  console.log('\n2️⃣ Testing authentication...');
  
  try {
    const response = await fetch(`${SERVER_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: TEST_EMAIL,
        password: TEST_PASSWORD
      })
    });
    
    const data = await response.json();
    
    if (response.ok && data.token) {
      console.log('✅ Login successful');
      console.log('👤 User:', data.user.username);
      console.log('🔑 Token received');
      return data.token;
    } else {
      console.log('❌ Login failed:', data.message);
      return null;
    }
  } catch (error) {
    console.log('❌ Login error:', error.message);
    return null;
  }
}

async function createTestFile() {
  console.log('\n3️⃣ Creating test file...');
  
  const testContent = `This is a test file for SickoScoop upload functionality.
Created at: ${new Date().toISOString()}
File size: Small text file for testing
Purpose: Verify upload system works correctly`;
  
  const testFileName = 'test-upload.txt';
  
  try {
    fs.writeFileSync(testFileName, testContent);
    console.log('✅ Test file created:', testFileName);
    console.log('📄 File size:', fs.statSync(testFileName).size, 'bytes');
    return testFileName;
  } catch (error) {
    console.log('❌ Failed to create test file:', error.message);
    return null;
  }
}

async function testUpload(token, testFile) {
  console.log('\n4️⃣ Testing file upload...');
  
  try {
    const form = new FormData();
    form.append('files', fs.createReadStream(testFile));
    
    console.log('📤 Uploading to:', `${SERVER_URL}/api/media/upload`);
    console.log('🔑 Using token:', token.substring(0, 20) + '...');
    
    const response = await fetch(`${SERVER_URL}/api/media/upload`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        ...form.getHeaders()
      },
      body: form
    });
    
    const responseText = await response.text();
    console.log('📥 Response status:', response.status);
    
    if (response.ok) {
      const data = JSON.parse(responseText);
      console.log('✅ Upload successful!');
      console.log('📁 Files uploaded:', data.files?.length || 0);
      if (data.files && data.files.length > 0) {
        console.log('🔗 File URL:', data.files[0].url);
        console.log('📊 File details:', {
          type: data.files[0].type,
          size: data.files[0].size,
          filename: data.files[0].filename
        });
      }
      if (data.statistics) {
        console.log('📊 Upload statistics:', data.statistics);
      }
      return true;
    } else {
      console.log('❌ Upload failed');
      console.log('📝 Response body:', responseText);
      
      try {
        const errorData = JSON.parse(responseText);
        console.log('🔍 Error details:', errorData);
      } catch (e) {
        console.log('🔍 Raw error response:', responseText);
      }
      
      return false;
    }
  } catch (error) {
    console.log('❌ Upload error:', error.message);
    console.log('🔍 Error details:', error);
    return false;
  }
}

async function testEnvironment() {
  console.log('\n5️⃣ Testing environment configuration...');
  
  const requiredEnvVars = [
    'MONGODB_URI',
    'JWT_SECRET', 
    'DO_SPACES_KEY',
    'DO_SPACES_SECRET',
    'DO_SPACES_BUCKET'
  ];
  
  let allConfigured = true;
  
  console.log('🔍 Checking environment variables...');
  requiredEnvVars.forEach(varName => {
    if (process.env[varName]) {
      console.log(`✅ ${varName} is configured`);
    } else {
      console.log(`❌ ${varName} is missing`);
      allConfigured = false;
    }
  });
  
  if (!allConfigured) {
    console.log('💡 Create a .env file with the missing variables');
    console.log('💡 Or set them as environment variables');
  }
  
  return allConfigured;
}

function cleanup(testFile) {
  console.log('\n6️⃣ Cleaning up...');
  
  try {
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
      console.log('✅ Test file deleted');
    }
  } catch (error) {
    console.log('⚠️ Could not delete test file:', error.message);
  }
}

async function runFullTest() {
  console.log('🚀 Starting comprehensive upload test...');
  console.log('⏰ Started at:', new Date().toLocaleString());
  
  // Test 1: Server connectivity
  const serverOk = await testServer();
  if (!serverOk) {
    console.log('\n❌ Test failed: Server not accessible');
    console.log('💡 Make sure your server is running:');
    console.log('   1. Check if enhanced-server.js exists in your project');
    console.log('   2. Run: node enhanced-server.js');
    console.log('   3. Server should start on port 3001');
    return;
  }
  
  // Test 2: Environment configuration
  const envOk = await testEnvironment();
  if (!envOk) {
    console.log('\n⚠️ Warning: Some environment variables are missing');
    console.log('💡 Upload test may fail without proper DigitalOcean Spaces config');
  }
  
  // Test 3: Authentication
  const token = await testLogin();
  if (!token) {
    console.log('\n❌ Test failed: Could not authenticate');
    console.log('💡 Make sure demo login is enabled in your server');
    console.log('💡 Or check if the server is properly configured');
    return;
  }
  
  // Test 4: File creation
  const testFile = await createTestFile();
  if (!testFile) {
    console.log('\n❌ Test failed: Could not create test file');
    return;
  }
  
  // Test 5: Upload
  const uploadOk = await testUpload(token, testFile);
  
  // Test 6: Cleanup
  cleanup(testFile);
  
  // Final results
  console.log('\n🏁 Test Results');
  console.log('==============');
  console.log(`Server Connection: ${serverOk ? '✅ Working' : '❌ Failed'}`);
  console.log(`Environment: ${envOk ? '✅ Complete' : '⚠️ Incomplete'}`);
  console.log(`Authentication: ${token ? '✅ Working' : '❌ Failed'}`);
  console.log(`File Upload: ${uploadOk ? '✅ Working' : '❌ Failed'}`);
  console.log('⏰ Completed at:', new Date().toLocaleString());
  
  if (uploadOk) {
    console.log('\n🎉 SUCCESS! Your upload system is working correctly.');
    console.log('🚀 You can now proceed with confidence to production deployment.');
  } else {
    console.log('\n🔧 ISSUES FOUND: Please check the error messages above.');
    console.log('💡 Common fixes:');
    console.log('   - Make sure enhanced-server.js exists and is running');
    console.log('   - Check your .env file has all required variables');
    console.log('   - Verify DigitalOcean Spaces credentials');
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled promise rejection:', reason);
  process.exit(1);
});

// Run the test
console.log('🎯 SickoScoop Upload Test Starting...');
runFullTest().catch(error => {
  console.error('\n💥 Test script error:', error);
  process.exit(1);
});