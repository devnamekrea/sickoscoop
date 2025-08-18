// ChatView.js - BSV Chat Component with Private Handles
import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  Key, 
  Users, 
  Send, 
  Copy, 
  Check, 
  AlertTriangle, 
  Eye, 
  EyeOff,
  RefreshCw,
  Plus,
  Share2,
  Zap,
  Lock,
  Unlock,
  CheckCircle,
  XCircle,
  Info,
  User,
  MessageCircle
} from 'lucide-react';

// Enhanced API helper
const getApiBase = () => {
  const hostname = window.location.hostname;
  if (hostname.includes('sickoscoop') || hostname.includes('netlify.app') || hostname.includes('digitalocean')) {
    return 'https://sickoscoop-backend-deo45.ondigitalocean.app/api';
  }
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return window.location.port === '3000' ? 'http://localhost:3001/api' : '/api';
  }
  return 'https://sickoscoop-backend-deo45.ondigitalocean.app/api';
};

const API_BASE = getApiBase();

const apiRequest = async (endpoint, options = {}) => {
  const url = `${API_BASE}${endpoint}`;
  const token = localStorage.getItem('authToken');
  
  const defaultOptions = {
    headers: {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
      ...options.headers
    },
    ...options
  };

  console.log('🌍 BSV Chat API Request:', { url, method: options.method || 'GET' });

  try {
    const response = await fetch(url, defaultOptions);
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('❌ BSV Chat API Request Failed:', { url, error: error.message });
    throw error;
  }
};

const ChatView = ({ user, chatFeatures, onClose }) => {
  // State management
  const [currentTab, setCurrentTab] = useState('handles');
  const [handles, setHandles] = useState([]);
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // BSV Status
  const [bsvStatus, setBsvStatus] = useState({
    hasBSVKeys: false,
    isReady: false,
    bsvAddress: null
  });
  
  // Handle management
  const [shareHandleEmail, setShareHandleEmail] = useState('');
  const [selectedHandle, setSelectedHandle] = useState(null);
  
  // Messaging
  const [selectedRecipient, setSelectedRecipient] = useState('');
  const [messageContent, setMessageContent] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  
  const messageInputRef = useRef(null);

  // Initialize BSV Chat on component mount
  useEffect(() => {
    console.log('🔐 BSV Chat Component Mounted');
    checkBSVStatus();
    loadHandles();
  }, []);

  // Check BSV key status
  const checkBSVStatus = async () => {
    try {
      setLoading(true);
      console.log('🔍 Checking BSV status...');
      
      const status = await apiRequest('/chat/bsv-status');
      setBsvStatus(status);
      
      console.log('✅ BSV Status:', status);
      
      if (!status.hasBSVKeys) {
        await initializeBSVKeys();
      }
    } catch (error) {
      console.error('❌ Error checking BSV status:', error);
      setError('Failed to check BSV status: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  // Initialize BSV keys
  const initializeBSVKeys = async () => {
    try {
      setLoading(true);
      console.log('🔑 Initializing BSV keys...');
      
      const result = await apiRequest('/chat/init-bsv', {
        method: 'POST'
      });
      
      setBsvStatus({
        hasBSVKeys: result.hasKeys,
        isReady: result.hasKeys,
        bsvAddress: result.bsvAddress
      });
      
      setSuccess('BSV cryptographic keys initialized successfully!');
      console.log('✅ BSV keys initialized:', result);
    } catch (error) {
      console.error('❌ Error initializing BSV keys:', error);
      setError('Failed to initialize BSV keys: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  // Load user handles
  const loadHandles = async () => {
    try {
      setLoading(true);
      console.log('📝 Loading handles...');
      
      // Try to get existing handles
      try {
        const result = await apiRequest('/chat/get-handles');
        if (result.success && result.ownHandles && result.ownHandles.length > 0) {
          setHandles(result.ownHandles);
          setSelectedHandle(result.ownHandles.find(h => h.isActive) || result.ownHandles[0]);
          console.log('✅ Handles loaded:', result.ownHandles.length);
          return;
        }
      } catch (error) {
        console.log('📝 No existing handles, creating new ones...');
      }
      
      // Create handles if none exist
      const initResult = await apiRequest('/chat/init-handles', {
        method: 'POST'
      });
      
      if (initResult.success && initResult.handles) {
        setHandles(initResult.handles);
        setSelectedHandle(initResult.handles.find(h => h.isActive) || initResult.handles[0]);
        setSuccess('Private handles created successfully!');
        console.log('✅ Handles created:', initResult.handles.length);
      }
    } catch (error) {
      console.error('❌ Error loading handles:', error);
      setError('Failed to load handles: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  // Share handle with another user
  const shareHandle = async (handleId, targetEmail) => {
    try {
      setLoading(true);
      console.log('🤝 Sharing handle:', { handleId, targetEmail });
      
      const result = await apiRequest('/chat/share-handle', {
        method: 'POST',
        body: JSON.stringify({
          handleId,
          targetUserEmail: targetEmail
        })
      });
      
      if (result.success) {
        setSuccess(`Handle ${handleId} shared with ${targetEmail}!`);
        setShareHandleEmail('');
        await loadHandles(); // Reload to get updated share counts
      }
    } catch (error) {
      console.error('❌ Error sharing handle:', error);
      setError('Failed to share handle: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  // Send BSV-signed message
  const sendMessage = async () => {
    if (!messageContent.trim() || !selectedRecipient.trim() || !selectedHandle) {
      setError('Please fill in all fields and select a handle');
      return;
    }

    try {
      setLoading(true);
      console.log('📨 Sending BSV-signed message...');
      
      const result = await apiRequest('/chat/send-message', {
        method: 'POST',
        body: JSON.stringify({
          senderHandle: selectedHandle.handle,
          recipientHandle: selectedRecipient,
          content: messageContent
        })
      });
      
      if (result.success) {
        setSuccess('Message sent successfully with BSV signature!');
        setMessageContent('');
        await loadMessages();
      }
    } catch (error) {
      console.error('❌ Error sending message:', error);
      setError('Failed to send message: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  // Load messages
  const loadMessages = async () => {
    try {
      const result = await apiRequest('/chat/get-messages');
      if (result.success) {
        setMessages(result.messages || []);
      }
    } catch (error) {
      console.error('❌ Error loading messages:', error);
    }
  };

  // Test BSV signing
  const testBSVSigning = async () => {
    try {
      setLoading(true);
      const testMessage = `Test message from ${user.username} at ${new Date().toISOString()}`;
      
      console.log('🧪 Testing BSV signing...');
      
      const result = await apiRequest('/chat/sign-message', {
        method: 'POST',
        body: JSON.stringify({ message: testMessage })
      });
      
      setSuccess('BSV signing test successful! Message cryptographically signed.');
      console.log('✅ BSV signature test result:', result);
    } catch (error) {
      console.error('❌ BSV signing test failed:', error);
      setError('BSV signing test failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  // Clear messages
  const clearMessages = () => {
    setError('');
    setSuccess('');
  };

  // Copy handle to clipboard
  const copyHandle = async (handle) => {
    try {
      await navigator.clipboard.writeText(handle);
      setSuccess(`Handle ${handle} copied to clipboard!`);
    } catch (error) {
      console.error('Failed to copy handle:', error);
    }
  };

  return (
    <div className="h-full flex flex-col bg-gradient-to-br from-slate-900/50 to-zinc-900/50">
      
      {/* Header with tabs */}
      <div className="flex-shrink-0 border-b border-slate-600/30 bg-slate-800/30">
        <div className="flex items-center justify-between p-4">
          <div className="flex space-x-1">
            <button
              onClick={() => setCurrentTab('handles')}
              className={`px-4 py-2 rounded-lg transition-all duration-200 text-sm font-medium ${
                currentTab === 'handles'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-slate-300 hover:text-white hover:bg-slate-700/50'
              }`}
            >
              <Key className="h-4 w-4 inline mr-2" />
              Handles
            </button>
            <button
              onClick={() => setCurrentTab('messages')}
              className={`px-4 py-2 rounded-lg transition-all duration-200 text-sm font-medium ${
                currentTab === 'messages'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-slate-300 hover:text-white hover:bg-slate-700/50'
              }`}
            >
              <MessageCircle className="h-4 w-4 inline mr-2" />
              Messages
            </button>
            <button
              onClick={() => setCurrentTab('security')}
              className={`px-4 py-2 rounded-lg transition-all duration-200 text-sm font-medium ${
                currentTab === 'security'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-slate-300 hover:text-white hover:bg-slate-700/50'
              }`}
            >
              <Shield className="h-4 w-4 inline mr-2" />
              Security
            </button>
          </div>
          
          {/* BSV Status Indicator */}
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${bsvStatus.isReady ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
            <span className="text-xs text-slate-400">
              {bsvStatus.isReady ? 'BSV Ready' : 'Initializing...'}
            </span>
          </div>
        </div>
      </div>

      {/* Messages */}
      {(error || success) && (
        <div className="flex-shrink-0 p-4 space-y-2">
          {error && (
            <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-3 flex items-start justify-between">
              <div className="flex items-start space-x-2">
                <XCircle className="h-4 w-4 text-red-400 mt-0.5 flex-shrink-0" />
                <span className="text-red-300 text-sm">{error}</span>
              </div>
              <button onClick={clearMessages} className="text-red-400 hover:text-red-300">
                ×
              </button>
            </div>
          )}
          {success && (
            <div className="bg-green-500/20 border border-green-500/50 rounded-lg p-3 flex items-start justify-between">
              <div className="flex items-start space-x-2">
                <CheckCircle className="h-4 w-4 text-green-400 mt-0.5 flex-shrink-0" />
                <span className="text-green-300 text-sm">{success}</span>
              </div>
              <button onClick={clearMessages} className="text-green-400 hover:text-green-300">
                ×
              </button>
            </div>
          )}
        </div>
      )}

      {/* Loading overlay */}
      {loading && (
        <div className="absolute inset-0 bg-black/30 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-slate-800/90 rounded-xl p-6 flex items-center space-x-3">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-400"></div>
            <span className="text-white">Processing...</span>
          </div>
        </div>
      )}

      {/* Tab Content */}
      <div className="flex-1 overflow-auto p-6">
        
        {/* Handles Tab */}
        {currentTab === 'handles' && (
          <div className="space-y-6">
            
            {/* Handle Overview */}
            <div className="bg-slate-800/30 rounded-xl p-6 border border-slate-600/30">
              <h3 className="text-xl font-semibold text-white mb-4 flex items-center space-x-2">
                <Key className="h-5 w-5 text-blue-400" />
                <span>Private Handles</span>
              </h3>
              <p className="text-slate-300 text-sm mb-4">
                Private handles allow selective disclosure while maintaining complete accountability. 
                Each handle is cryptographically linked to your verified identity.
              </p>
              
              {handles.length === 0 ? (
                <div className="text-center py-8">
                  <Key className="h-12 w-12 text-slate-500 mx-auto mb-3" />
                  <p className="text-slate-400 mb-4">No handles generated yet</p>
                  <button
                    onClick={loadHandles}
                    disabled={loading}
                    className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50"
                  >
                    Generate Handles
                  </button>
                </div>
              ) : (
                <div className="grid gap-3">
                  {handles.map((handle, index) => (
                    <div 
                      key={index}
                      className={`p-4 rounded-lg border-2 transition-all duration-200 cursor-pointer ${
                        selectedHandle?.handle === handle.handle
                          ? 'border-blue-500 bg-blue-500/10'
                          : 'border-slate-600/30 bg-slate-700/20 hover:border-slate-500/50'
                      }`}
                      onClick={() => setSelectedHandle(handle)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className={`w-3 h-3 rounded-full ${handle.isActive ? 'bg-green-500' : 'bg-slate-500'}`}></div>
                          <div>
                            <div className="font-mono text-white font-semibold">{handle.handle}</div>
                            <div className="text-xs text-slate-400">
                              {handle.isActive ? 'Active' : 'Backup'} • 
                              Shared with {handle.sharedWithCount || 0} users
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              copyHandle(handle.handle);
                            }}
                            className="p-2 text-slate-400 hover:text-white hover:bg-slate-600/50 rounded-lg transition-colors"
                            title="Copy handle"
                          >
                            <Copy className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Share Handle */}
            {selectedHandle && (
              <div className="bg-slate-800/30 rounded-xl p-6 border border-slate-600/30">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
                  <Share2 className="h-5 w-5 text-green-400" />
                  <span>Share Handle: {selectedHandle.handle}</span>
                </h3>
                <p className="text-slate-300 text-sm mb-4">
                  Share this handle with another verified user to enable secure messaging.
                </p>
                
                <div className="flex space-x-3">
                  <input
                    type="email"
                    value={shareHandleEmail}
                    onChange={(e) => setShareHandleEmail(e.target.value)}
                    placeholder="Enter user's email address"
                    className="flex-1 px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                  />
                  <button
                    onClick={() => shareHandle(selectedHandle.handle, shareHandleEmail)}
                    disabled={!shareHandleEmail.trim() || loading}
                    className="px-6 py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Share
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Messages Tab */}
        {currentTab === 'messages' && (
          <div className="space-y-6">
            
            {/* Send Message */}
            <div className="bg-slate-800/30 rounded-xl p-6 border border-slate-600/30">
              <h3 className="text-xl font-semibold text-white mb-4 flex items-center space-x-2">
                <Send className="h-5 w-5 text-purple-400" />
                <span>Send BSV-Signed Message</span>
              </h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">From Handle</label>
                  <select
                    value={selectedHandle?.handle || ''}
                    onChange={(e) => {
                      const handle = handles.find(h => h.handle === e.target.value);
                      setSelectedHandle(handle);
                    }}
                    className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                  >
                    <option value="">Select your handle</option>
                    {handles.filter(h => h.isActive).map(handle => (
                      <option key={handle.handle} value={handle.handle}>
                        {handle.handle} (shared with {handle.sharedWithCount || 0})
                      </option>
                    ))}
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">To Handle</label>
                  <input
                    type="text"
                    value={selectedRecipient}
                    onChange={(e) => setSelectedRecipient(e.target.value)}
                    placeholder="Enter recipient's handle (e.g., SK-XXXX-XX-XX)"
                    className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">Message</label>
                  <textarea
                    ref={messageInputRef}
                    value={messageContent}
                    onChange={(e) => setMessageContent(e.target.value)}
                    placeholder="Type your message..."
                    rows={4}
                    className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/50 resize-none"
                  />
                </div>
                
                <button
                  onClick={sendMessage}
                  disabled={!messageContent.trim() || !selectedRecipient.trim() || !selectedHandle || loading}
                  className="w-full px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
                >
                  <Zap className="h-4 w-4" />
                  <span>Send with BSV Signature</span>
                </button>
              </div>
            </div>

            {/* Message History */}
            <div className="bg-slate-800/30 rounded-xl p-6 border border-slate-600/30">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white flex items-center space-x-2">
                  <MessageCircle className="h-5 w-5 text-blue-400" />
                  <span>Message History</span>
                </h3>
                <button
                  onClick={loadMessages}
                  className="p-2 text-slate-400 hover:text-white hover:bg-slate-600/50 rounded-lg transition-colors"
                  title="Refresh messages"
                >
                  <RefreshCw className="h-4 w-4" />
                </button>
              </div>
              
              {messages.length === 0 ? (
                <div className="text-center py-8">
                  <MessageCircle className="h-12 w-12 text-slate-500 mx-auto mb-3" />
                  <p className="text-slate-400">No messages yet</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {messages.map((message, index) => (
                    <div key={index} className="p-4 bg-slate-700/30 rounded-lg border border-slate-600/20">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-sm text-blue-400">
                            {message.senderHandle}
                          </span>
                          <span className="text-slate-500">→</span>
                          <span className="font-mono text-sm text-purple-400">
                            {message.recipientHandle}
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          {message.signatureValid ? (
                            <CheckCircle className="h-4 w-4 text-green-400" title="Signature valid" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-red-400" title="Signature invalid - possible surveillance!" />
                          )}
                          <span className="text-xs text-slate-500">
                            {new Date(message.timestamp).toLocaleString()}
                          </span>
                        </div>
                      </div>
                      <p className="text-slate-200">{message.content}</p>
                      {message.surveillanceDetected && (
                        <div className="mt-2 p-2 bg-red-500/20 border border-red-500/50 rounded text-red-300 text-xs">
                          ⚠️ SURVEILLANCE DETECTED: Message signature verification failed!
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Security Tab */}
        {currentTab === 'security' && (
          <div className="space-y-6">
            
            {/* BSV Status */}
            <div className="bg-slate-800/30 rounded-xl p-6 border border-slate-600/30">
              <h3 className="text-xl font-semibold text-white mb-4 flex items-center space-x-2">
                <Shield className="h-5 w-5 text-green-400" />
                <span>BSV Security Status</span>
              </h3>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-slate-700/30 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full ${bsvStatus.hasBSVKeys ? 'bg-green-500' : 'bg-red-500'}`}></div>
                    <span className="text-white">BSV Keys Initialized</span>
                  </div>
                  <span className={`text-sm ${bsvStatus.hasBSVKeys ? 'text-green-400' : 'text-red-400'}`}>
                    {bsvStatus.hasBSVKeys ? 'Yes' : 'No'}
                  </span>
                </div>
                
                <div className="flex items-center justify-between p-4 bg-slate-700/30 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full ${bsvStatus.isReady ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
                    <span className="text-white">System Ready</span>
                  </div>
                  <span className={`text-sm ${bsvStatus.isReady ? 'text-green-400' : 'text-yellow-400'}`}>
                    {bsvStatus.isReady ? 'Ready' : 'Initializing'}
                  </span>
                </div>
                
                {bsvStatus.bsvAddress && (
                  <div className="p-4 bg-slate-700/30 rounded-lg">
                    <div className="flex items-center justify-between">
                      <span className="text-white">BSV Address</span>
                      <button
                        onClick={() => copyHandle(bsvStatus.bsvAddress)}
                        className="p-1 text-slate-400 hover:text-white hover:bg-slate-600/50 rounded transition-colors"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                    </div>
                    <div className="mt-2 font-mono text-sm text-blue-400 break-all">
                      {bsvStatus.bsvAddress}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Security Features */}
            <div className="bg-slate-800/30 rounded-xl p-6 border border-slate-600/30">
              <h3 className="text-lg font-semibold text-white mb-4">Security Features</h3>
              
              <div className="space-y-3">
                <div className="flex items-center space-x-3 p-3 bg-slate-700/20 rounded-lg">
                  <Lock className="h-5 w-5 text-blue-400" />
                  <div>
                    <div className="text-white font-medium">Cryptographic Signatures</div>
                    <div className="text-xs text-slate-400">Every message signed with BSV private key</div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3 p-3 bg-slate-700/20 rounded-lg">
                  <Eye className="h-5 w-5 text-purple-400" />
                  <div>
                    <div className="text-white font-medium">Surveillance Detection</div>
                    <div className="text-xs text-slate-400">Automatic detection of message tampering</div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3 p-3 bg-slate-700/20 rounded-lg">
                  <Users className="h-5 w-5 text-green-400" />
                  <div>
                    <div className="text-white font-medium">Verified Identity</div>
                    <div className="text-xs text-slate-400">All users linked to verified accounts</div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3 p-3 bg-slate-700/20 rounded-lg">
                  <Key className="h-5 w-5 text-orange-400" />
                  <div>
                    <div className="text-white font-medium">Private Handles</div>
                    <div className="text-xs text-slate-400">Selective disclosure with full audit trail</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Test BSV Signing */}
            <div className="bg-slate-800/30 rounded-xl p-6 border border-slate-600/30">
              <h3 className="text-lg font-semibold text-white mb-4">Test BSV Signing</h3>
              <p className="text-slate-300 text-sm mb-4">
                Test the BSV cryptographic signing system to ensure everything is working correctly.
              </p>
              <button
                onClick={testBSVSigning}
                disabled={loading || !bsvStatus.isReady}
                className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
              >
                <Zap className="h-4 w-4" />
                <span>Test BSV Signature</span>
              </button>
            </div>

            {/* Advanced Options */}
            <div className="bg-slate-800/30 rounded-xl p-6 border border-slate-600/30">
              <button
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="flex items-center justify-between w-full text-left"
              >
                <h3 className="text-lg font-semibold text-white">Advanced Options</h3>
                <div className={`transform transition-transform ${showAdvanced ? 'rotate-180' : ''}`}>
                  {showAdvanced ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </div>
              </button>
              
              {showAdvanced && (
                <div className="mt-4 space-y-4">
                  <div className="p-4 bg-slate-700/20 rounded-lg">
                    <div className="text-white font-medium mb-2">Feature Status</div>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Chat Enabled:</span>
                        <span className={chatFeatures?.chatEnabled ? 'text-green-400' : 'text-red-400'}>
                          {chatFeatures?.chatEnabled ? 'Yes' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">BSV Chat Enabled:</span>
                        <span className={chatFeatures?.bsvChatEnabled ? 'text-green-400' : 'text-red-400'}>
                          {chatFeatures?.bsvChatEnabled ? 'Yes' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Beta User:</span>
                        <span className={chatFeatures?.isBetaUser ? 'text-blue-400' : 'text-slate-400'}>
                          {chatFeatures?.isBetaUser ? 'Yes' : 'No'}
                        </span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="p-4 bg-orange-500/10 border border-orange-500/30 rounded-lg">
                    <div className="flex items-start space-x-2">
                      <Info className="h-4 w-4 text-orange-400 mt-0.5 flex-shrink-0" />
                      <div className="text-orange-300 text-xs">
                        <strong>Beta Notice:</strong> BSV Chat is currently in beta testing. 
                        All messages are cryptographically signed and surveillance detection is active. 
                        Report any issues to the development team.
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ChatView;