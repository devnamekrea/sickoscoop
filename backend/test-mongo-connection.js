// test-mongo-connection.js
const mongoose = require('mongoose');
require('dotenv').config();

async function testConnection() {
  try {
    console.log('🔄 Testing MongoDB connection...');
    
    const mongoUri = process.env.MONGODB_URI;
    
    if (!mongoUri) {
      console.error('❌ MONGODB_URI not found in environment variables');
      console.log('💡 Create a .env file with: MONGODB_URI=your-connection-string');
      process.exit(1);
    }
    
    console.log('📍 URI Preview:', mongoUri.replace(/:([^:@]+)@/, ':***@'));
    
    const options = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      tls: true,
      authSource: 'admin',
      serverSelectionTimeoutMS: 30000,
    };
    
    await mongoose.connect(mongoUri, options);
    console.log('✅ Connection successful!');
    
    // Test a simple operation
    const testResult = await mongoose.connection.db.admin().ping();
    console.log('📊 Ping result:', testResult);
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
    console.error('🔧 Check your MONGODB_URI format and credentials');
    process.exit(1);
  }
}

testConnection();
