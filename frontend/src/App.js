import React, { useState, useEffect, useRef } from 'react';
import { MessageSquare, Heart, Share2, User, Settings, Shield, Send, Home, Users, Lock, Eye, EyeOff, AlertCircle } from 'lucide-react';

// API Configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';
const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:5000';

// API Helper Functions
const apiCall = async (endpoint, options = {}) => {
  const token = localStorage.getItem('authToken');
  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options.headers,
    },
    ...options,
  };

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Network error');
    }
    
    return data;
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
};

const SickoScoopApp = () => {
  const [currentUser, setCurrentUser] = useState(null);
  const [currentView, setCurrentView] = useState('landing');
  const [posts, setPosts] = useState([]);
  const [newPost, setNewPost] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const [signupForm, setSignupForm] = useState({ name: '', email: '', password: '' });
  const [selectedChat, setSelectedChat] = useState(null);
  const [chatMessage, setChatMessage] = useState('');
  const [chats, setChats] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [socket, setSocket] = useState(null);
  const messagesEndRef = useRef(null);

  // Initialize socket connection
  useEffect(() => {
    if (currentUser && !socket) {
      // Dynamic import for socket.io-client
      import('socket.io-client').then((io) => {
        const newSocket = io.default(SOCKET_URL);
        setSocket(newSocket);

        newSocket.on('new-message', (message) => {
          if (selectedChat && message.chatId === selectedChat._id) {
            setSelectedChat(prev => ({
              ...prev,
              messages: [...prev.messages, message]
            }));
          }
          loadChats(); // Refresh chat list
        });

        return () => newSocket.close();
      });
    }
  }, [currentUser, selectedChat]);

  // Auto-scroll chat messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [selectedChat?.messages]);

  // Check for existing auth token on app load
  useEffect(() => {
    const token = localStorage.getItem('authToken');
    const userData = localStorage.getItem('userData');
    
    if (token && userData) {
      try {
        const user = JSON.parse(userData);
        setCurrentUser(user);
        setCurrentView('feed');
        loadPosts();
        loadChats();
      } catch (error) {
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
      }
    }
  }, []);

  const handleError = (error) => {
    setError(error.message || 'An error occurred');
    setTimeout(() => setError(''), 5000);
  };

  const handleLogin = async () => {
    setLoading(true);
    setError('');
    
    try {
      const response = await apiCall('/auth/login', {
        method: 'POST',
        body: JSON.stringify(loginForm),
      });

      localStorage.setItem('authToken', response.token);
      localStorage.setItem('userData', JSON.stringify(response.user));
      setCurrentUser(response.user);
      setCurrentView('feed');
      await loadPosts();
      await loadChats();
    } catch (error) {
      handleError(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = async () => {
    setLoading(true);
    setError('');
    
    try {
      const response = await apiCall('/auth/signup', {
        method: 'POST',
        body: JSON.stringify(signupForm),
      });

      localStorage.setItem('authToken', response.token);
      localStorage.setItem('userData', JSON.stringify(response.user));
      setCurrentUser(response.user);
      setCurrentView('feed');
      await loadPosts();
    } catch (error) {
      handleError(error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('userData');
    setCurrentUser(null);
    setCurrentView('landing');
    setPosts([]);
    setChats([]);
    if (socket) {
      socket.disconnect();
      setSocket(null);
    }
  };

  const loadPosts = async () => {
    try {
      const response = await apiCall('/posts');
      setPosts(response);
    } catch (error) {
      handleError(error);
    }
  };

  const loadChats = async () => {
    try {
      const response = await apiCall('/chats');
      setChats(response);
    } catch (error) {
      handleError(error);
    }
  };

  const handlePost = async () => {
    if (!newPost.trim()) return;
    
    setLoading(true);
    try {
      const response = await apiCall('/posts', {
        method: 'POST',
        body: JSON.stringify({ content: newPost }),
      });

      setPosts([response, ...posts]);
      setNewPost('');
    } catch (error) {
      handleError(error);
    } finally {
      setLoading(false);
    }
  };

  const likePost = async (postId) => {
    try {
      const response = await apiCall(`/posts/${postId}/like`, {
        method: 'POST',
      });

      setPosts(posts.map(post => 
        post._id === postId 
          ? { ...post, likes: response.liked 
              ? [...post.likes, currentUser.id] 
              : post.likes.filter(id => id !== currentUser.id) }
          : post
      ));
    } catch (error) {
      handleError(error);
    }
  };

  const sendMessage = async () => {
    if (!chatMessage.trim() || !selectedChat || !socket) return;

    const messageData = {
      chatId: selectedChat._id,
      content: chatMessage.trim(),
      senderId: currentUser.id
    };

    socket.emit('send-message', messageData);
    setChatMessage('');
  };

  const formatTimeAgo = (date) => {
    const now = new Date();
    const postDate = new Date(date);
    const diffInMinutes = Math.floor((now - postDate) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return `${Math.floor(diffInMinutes / 1440)}d ago`;
  };

  const ErrorAlert = () => error && (
    <div className="fixed top-4 right-4 bg-red-500/90 text-white px-4 py-3 rounded-lg shadow-lg z-50 flex items-center space-x-2">
      <AlertCircle className="w-5 h-5" />
      <span>{error}</span>
    </div>
  );

  const LoadingSpinner = () => (
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-yellow-400"></div>
  );

  const renderLandingPage = () => (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-indigo-900 to-blue-900 relative overflow-hidden">
      <ErrorAlert />
      
      {/* Ornate Background Pattern */}
      <div className="absolute inset-0 opacity-20">
        <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-yellow-400 via-transparent to-purple-600"></div>
        <div className="absolute top-20 left-20 w-32 h-32 border-2 border-yellow-400 rounded-full opacity-30"></div>
        <div className="absolute bottom-20 right-20 w-24 h-24 border border-yellow-400 rotate-45 opacity-40"></div>
        <div className="absolute top-1/2 left-1/3 w-16 h-16 bg-yellow-400 rounded-full opacity-20"></div>
      </div>

      <div className="relative z-10 flex flex-col items-center justify-center min-h-screen px-4">
        {/* Logo */}
        <div className="mb-8 text-center">
          <div className="w-24 h-24 mx-auto mb-4 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center border-4 border-yellow-300 shadow-2xl">
            <span className="text-3xl font-bold text-purple-900">SS</span>
          </div>
          <h1 className="text-6xl font-bold bg-gradient-to-r from-yellow-400 via-yellow-300 to-yellow-500 bg-clip-text text-transparent mb-2">
            SickoScoop
          </h1>
          <p className="text-xl text-yellow-200 italic">Where Authenticity Reigns Supreme</p>
        </div>

        {/* Main Message */}
        <div className="bg-black/40 backdrop-blur-md border border-yellow-400/30 rounded-2xl p-8 mb-8 max-w-2xl mx-auto text-center shadow-2xl">
          <h2 className="text-4xl font-bold text-yellow-300 mb-4 tracking-wide">
            STOP STALKERS ON SICKOSCOOP
          </h2>
          <p className="text-lg text-white/90 leading-relaxed mb-6">
            Join a revolutionary social platform built on transparency, genuine connections, and user safety. 
            Our advanced protection systems ensure authentic communication while keeping predators at bay.
          </p>
          <div className="flex items-center justify-center space-x-4 text-yellow-300">
            <Shield className="w-6 h-6" />
            <span className="text-sm">Verified Identities</span>
            <Lock className="w-6 h-6" />
            <span className="text-sm">Secure Conversations</span>
            <Heart className="w-6 h-6" />
            <span className="text-sm">Genuine Connections</span>
          </div>
        </div>

        {/* Auth Buttons */}
        <div className="flex space-x-4">
          <button
            onClick={() => setCurrentView('login')}
            className="px-8 py-3 bg-gradient-to-r from-yellow-500 to-yellow-600 text-purple-900 font-bold rounded-xl hover:from-yellow-400 hover:to-yellow-500 transition-all duration-300 shadow-lg transform hover:scale-105"
          >
            Sign In
          </button>
          <button
            onClick={() => setCurrentView('signup')}
            className="px-8 py-3 bg-transparent border-2 border-yellow-400 text-yellow-300 font-bold rounded-xl hover:bg-yellow-400 hover:text-purple-900 transition-all duration-300 shadow-lg transform hover:scale-105"
          >
            Join Now
          </button>
        </div>
      </div>
    </div>
  );

  const renderAuth = (type) => (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-indigo-900 to-blue-900 flex items-center justify-center px-4">
      <ErrorAlert />
      
      <div className="bg-black/40 backdrop-blur-md border border-yellow-400/30 rounded-2xl p-8 max-w-md w-full shadow-2xl">
        <div className="text-center mb-6">
          <div className="w-16 h-16 mx-auto mb-4 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center">
            <span className="text-xl font-bold text-purple-900">SS</span>
          </div>
          <h2 className="text-2xl font-bold text-yellow-300 mb-2">
            {type === 'login' ? 'Welcome Back' : 'Join SickoScoop'}
          </h2>
          <p className="text-white/70 text-sm">
            {type === 'login' ? 'Continue your authentic journey' : 'Start building genuine connections'}
          </p>
        </div>

        <div>
          {type === 'signup' && (
            <div className="mb-4">
              <input
                type="text"
                placeholder="Full Name"
                value={signupForm.name}
                onChange={(e) => setSignupForm({...signupForm, name: e.target.value})}
                className="w-full px-4 py-3 bg-white/10 border border-yellow-400/30 rounded-xl text-white placeholder-white/50 focus:outline-none focus:border-yellow-400 focus:bg-white/20 transition-all"
                disabled={loading}
              />
            </div>
          )}
          
          <div className="mb-4">
            <input
              type="email"
              placeholder="Email Address"
              value={type === 'login' ? loginForm.email : signupForm.email}
              onChange={(e) => {
                if (type === 'login') {
                  setLoginForm({...loginForm, email: e.target.value});
                } else {
                  setSignupForm({...signupForm, email: e.target.value});
                }
              }}
              className="w-full px-4 py-3 bg-white/10 border border-yellow-400/30 rounded-xl text-white placeholder-white/50 focus:outline-none focus:border-yellow-400 focus:bg-white/20 transition-all"
              disabled={loading}
            />
          </div>

          <div className="mb-6 relative">
            <input
              type={showPassword ? "text" : "password"}
              placeholder="Password"
              value={type === 'login' ? loginForm.password : signupForm.password}
              onChange={(e) => {
                if (type === 'login') {
                  setLoginForm({...loginForm, password: e.target.value});
                } else {
                  setSignupForm({...signupForm, password: e.target.value});
                }
              }}
              className="w-full px-4 py-3 bg-white/10 border border-yellow-400/30 rounded-xl text-white placeholder-white/50 focus:outline-none focus:border-yellow-400 focus:bg-white/20 transition-all pr-12"
              disabled={loading}
            />
            <button
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-white/50 hover:text-yellow-400 transition-colors"
              disabled={loading}
            >
              {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>

          <button
            onClick={type === 'login' ? handleLogin : handleSignup}
            disabled={loading}
            className="w-full px-4 py-3 bg-gradient-to-r from-yellow-500 to-yellow-600 text-purple-900 font-bold rounded-xl hover:from-yellow-400 hover:to-yellow-500 transition-all duration-300 shadow-lg mb-4 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
          >
            {loading ? <LoadingSpinner /> : (type === 'login' ? 'Sign In' : 'Create Account')}
          </button>
        </div>

        <div className="text-center">
          <button
            onClick={() => setCurrentView(type === 'login' ? 'signup' : 'login')}
            className="text-yellow-400 hover:text-yellow-300 text-sm transition-colors"
            disabled={loading}
          >
            {type === 'login' ? "Don't have an account? Sign up" : "Already have an account? Sign in"}
          </button>
        </div>

        <button
          onClick={() => setCurrentView('landing')}
          className="mt-4 w-full text-white/50 hover:text-white text-sm transition-colors"
          disabled={loading}
        >
          ← Back to Home
        </button>
      </div>
    </div>
  );

  const renderNavigation = () => (
    <nav className="bg-gradient-to-r from-purple-900 via-indigo-900 to-blue-900 border-b border-yellow-400/30 px-4 py-3">
      <div className="max-w-6xl mx-auto flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="w-10 h-10 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center">
            <span className="text-sm font-bold text-purple-900">SS</span>
          </div>
          <span className="text-xl font-bold text-yellow-300">SickoScoop</span>
        </div>

        <div className="flex items-center space-x-6">
          <button
            onClick={() => setCurrentView('feed')}
            className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors ${
              currentView === 'feed' ? 'bg-yellow-400/20 text-yellow-300' : 'text-white/70 hover:text-yellow-300'
            }`}
          >
            <Home className="w-5 h-5" />
            <span>Feed</span>
          </button>
          
          <button
            onClick={() => setCurrentView('profile')}
            className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors ${
              currentView === 'profile' ? 'bg-yellow-400/20 text-yellow-300' : 'text-white/70 hover:text-yellow-300'
            }`}
          >
            <User className="w-5 h-5" />
            <span>Profile</span>
          </button>

          <button
            onClick={() => {
              setCurrentView('chat');
              loadChats();
            }}
            className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors ${
              currentView === 'chat' ? 'bg-yellow-400/20 text-yellow-300' : 'text-white/70 hover:text-yellow-300'
            }`}
          >
            <MessageSquare className="w-5 h-5" />
            <span>Chat</span>
          </button>

          <div className="flex items-center space-x-3">
            <span className="text-white/70 text-sm">
              Welcome, {currentUser?.name || 'User'}
            </span>
            <button
              onClick={handleLogout}
              className="text-white/70 hover:text-red-400 transition-colors"
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    </nav>
  );

  const renderFeed = () => (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-indigo-900">
      <ErrorAlert />
      {renderNavigation()}
      
      <div className="max-w-2xl mx-auto px-4 py-6">
        {/* Post Creation */}
        <div className="bg-black/40 backdrop-blur-md border border-yellow-400/30 rounded-2xl p-6 mb-6 shadow-xl">
          <div className="flex items-start space-x-4">
            <div className="w-12 h-12 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center">
              <span className="text-lg">{currentUser?.avatar || '✨'}</span>
            </div>
            <div className="flex-1">
              <textarea
                value={newPost}
                onChange={(e) => setNewPost(e.target.value)}
                placeholder="Share something authentic..."
                className="w-full bg-transparent text-white placeholder-white/50 resize-none focus:outline-none text-lg"
                rows="3"
                disabled={loading}
              />
              <div className="flex justify-between items-center mt-4">
                <span className="text-white/50 text-sm">✨ Transparency encouraged</span>
                <button
                  onClick={handlePost}
                  disabled={!newPost.trim() || loading}
                  className="px-6 py-2 bg-gradient-to-r from-yellow-500 to-yellow-600 text-purple-900 font-semibold rounded-lg hover:from-yellow-400 hover:to-yellow-500 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
                >
                  {loading ? <LoadingSpinner /> : <span>Post</span>}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Posts */}
        <div className="space-y-6">
          {posts.map(post => (
            <div key={post._id || post.id} className="bg-black/40 backdrop-blur-md border border-yellow-400/30 rounded-2xl p-6 shadow-xl">
              <div className="flex items-start space-x-4">
                <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-full flex items-center justify-center">
                  <span className="text-lg">{post.author?.avatar || '👤'}</span>
                </div>
                <div className="flex-1">
                  <div className="flex items-center space-x-2 mb-2">
                    <span className="font-semibold text-white">{post.author?.name || 'Anonymous'}</span>
                    {post.author?.verified && <Shield className="w-4 h-4 text-yellow-400" />}
                    <span className="text-white/50 text-sm">{formatTimeAgo(post.createdAt || post.timestamp)}</span>
                  </div>
                  <p className="text-white/90 mb-4 leading-relaxed">{post.content}</p>
                  <div className="flex items-center space-x-6">
                    <button
                      onClick={() => likePost(post._id || post.id)}
                      className={`flex items-center space-x-2 transition-colors ${
                        post.likes?.includes(currentUser?.id) 
                          ? 'text-red-400' 
                          : 'text-white/60 hover:text-red-400'
                      }`}
                    >
                      <Heart className="w-5 h-5" />
                      <span>{Array.isArray(post.likes) ? post.likes.length : post.likes || 0}</span>
                    </button>
                    <button className="flex items-center space-x-2 text-white/60 hover:text-blue-400 transition-colors">
                      <MessageSquare className="w-5 h-5" />
                      <span>{post.comments?.length || post.comments || 0}</span>
                    </button>
                    <button className="flex items-center space-x-2 text-white/60 hover:text-green-400 transition-colors">
                      <Share2 className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))}
          
          {posts.length === 0 && (
            <div className="text-center py-12">
              <div className="text-white/50 text-lg mb-2">No posts yet</div>
              <div className="text-white/30">Be the first to share something authentic!</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  const renderProfile = () => (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-indigo-900">
      <ErrorAlert />
      {renderNavigation()}
      
      <div className="max-w-4xl mx-auto px-4 py-6">
        <div className="bg-black/40 backdrop-blur-md border border-yellow-400/30 rounded-2xl p-8 shadow-xl">
          <div className="flex items-start space-x-6 mb-8">
            <div className="w-24 h-24 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center">
              <span className="text-3xl">{currentUser?.avatar || '✨'}</span>
            </div>
            <div className="flex-1">
              <div className="flex items-center space-x-3 mb-2">
                <h1 className="text-3xl font-bold text-white">{currentUser?.name}</h1>
                {currentUser?.verified && <Shield className="w-6 h-6 text-yellow-400" />}
              </div>
              <p className="text-white/70 mb-4">Authentic communication advocate • Building genuine connections</p>
              <div className="flex space-x-6 text-sm">
                <span className="text-white/60"><strong className="text-white">127</strong> Following</span>
                <span className="text-white/60"><strong className="text-white">1.2K</strong> Followers</span>
                <span className="text-white/60"><strong className="text-white">{posts.filter(p => p.author?.name === currentUser?.name).length}</strong> Posts</span>
              </div>
            </div>
            <button className="px-6 py-2 bg-gradient-to-r from-yellow-500 to-yellow-600 text-purple-900 font-semibold rounded-lg hover:from-yellow-400 hover:to-yellow-500 transition-all">
              Edit Profile
            </button>
          </div>

          <div className="border-t border-yellow-400/30 pt-8">
            <h2 className="text-xl font-semibold text-white mb-6">Recent Posts</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {posts.filter(post => post.author?.name === currentUser?.name).map(post => (
                <div key={post._id || post.id} className="bg-white/5 border border-yellow-400/20 rounded-xl p-4">
                  <p className="text-white/90 mb-3">{post.content}</p>
                  <div className="flex items-center justify-between text-sm text-white/50">
                    <span>{formatTimeAgo(post.createdAt || post.timestamp)}</span>
                    <div className="flex space-x-4">
                      <span>❤️ {Array.isArray(post.likes) ? post.likes.length : post.likes || 0}</span>
                      <span>💬 {post.comments?.length || post.comments || 0}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            
            {posts.filter(post => post.author?.name === currentUser?.name).length === 0 && (
              <div className="text-center py-8 text-white/50">
                You haven't posted anything yet. Share your first authentic thought!
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );

  const renderChat = () => (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-indigo-900">
      <ErrorAlert />
      {renderNavigation()}
      
      <div className="max-w-6xl mx-auto px-4 py-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 h-[calc(100vh-200px)]">
          {/* Chat List */}
          <div className="bg-black/40 backdrop-blur-md border border-yellow-400/30 rounded-2xl p-4 shadow-xl">
            <h2 className="text-xl font-semibold text-white mb-4">Messages</h2>
            <div className="space-y-2">
              {chats.map(chat => {
                const otherUser = chat.participants?.find(p => p._id !== currentUser?.id);
                const lastMessage = chat.messages?.[chat.messages.length - 1];
                
                return (
                  <button
                    key={chat._id}
                    onClick={() => {
                      setSelectedChat(chat);
                      if (socket) {
                        socket.emit('join-chat', chat._id);
                      }
                    }}
                    className={`w-full p-3 rounded-xl text-left transition-colors ${
                      selectedChat?._id === chat._id ? 'bg-yellow-400/20' : 'hover:bg-white/5'
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-full flex items-center justify-center">
                        <span>{otherUser?.avatar || '👤'}</span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-white">{otherUser?.name || 'Unknown'}</span>
                          <span className="text-xs text-white/50">
                            {lastMessage ? formatTimeAgo(lastMessage.createdAt) : ''}
                          </span>
                        </div>
                        <p className="text-sm text-white/70 truncate">
                          {lastMessage?.content || 'No messages yet'}
                        </p>
                      </div>
                    </div>
                  </button>
                );
              })}
              
              {chats.length === 0 && (
                <div className="text-center py-8 text-white/50">
                  No conversations yet. Start connecting with others!
                </div>
              )}
            </div>
          </div>

          {/* Chat Window */}
          <div className="md:col-span-2 bg-black/40 backdrop-blur-md border border-yellow-400/30 rounded-2xl shadow-xl flex flex-col">
            {selectedChat ? (
              <>
                {/* Chat Header */}
                <div className="p-4 border-b border-yellow-400/30">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-full flex items-center justify-center">
                      <span>{selectedChat.participants?.find(p => p._id !== currentUser?.id)?.avatar || '👤'}</span>
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-medium text-white">
                          {selectedChat.participants?.find(p => p._id !== currentUser?.id)?.name || 'Unknown'}
                        </span>
                        <Shield className="w-4 h-4 text-yellow-400" />
                      </div>
                      <span className="text-sm text-green-400">● Online</span>
                    </div>
                  </div>
                </div>

                {/* Messages */}
                <div className="flex-1 p-4 overflow-y-auto">
                  <div className="space-y-4">
                    {selectedChat.messages?.map((message, index) => {
                      const isOwnMessage = message.sender?._id === currentUser?.id || message.sender === currentUser?.id;
                      
                      return (
                        <div key={index} className={`flex ${isOwnMessage ? 'justify-end' : 'justify-start'}`}>
                          <div className={`rounded-2xl p-3 max-w-xs ${
                            isOwnMessage 
                              ? 'bg-gradient-to-r from-yellow-500 to-yellow-600 rounded-tr-md'
                              : 'bg-white/10 rounded-tl-md'
                          }`}>
                            <p className={isOwnMessage ? 'text-purple-900' : 'text-white/90'}>
                              {message.content}
                            </p>
                            <span className={`text-xs ${
                              isOwnMessage ? 'text-purple-700' : 'text-white/50'
                            }`}>
                              {formatTimeAgo(message.createdAt)}
                            </span>
                          </div>
                        </div>
                      );
                    }) || []}
                    <div ref={messagesEndRef} />
                  </div>
                </div>

                {/* Message Input */}
                <div className="p-4 border-t border-yellow-400/30">
                  <div className="flex space-x-3">
                    <input
                      type="text"
                      value={chatMessage}
                      onChange={(e) => setChatMessage(e.target.value)}
                      placeholder="Type a message..."
                      className="flex-1 bg-white/10 border border-yellow-400/30 rounded-xl px-4 py-2 text-white placeholder-white/50 focus:outline-none focus:border-yellow-400"
                      onKeyPress={(e) => {
                        if (e.key === 'Enter') {
                          sendMessage();
                        }
                      }}
                    />
                    <button 
                      onClick={sendMessage}
                      disabled={!chatMessage.trim()}
                      className="p-2 bg-gradient-to-r from-yellow-500 to-yellow-600 text-purple-900 rounded-xl hover:from-yellow-400 hover:to-yellow-500 transition-all disabled:opacity-50"
                    >
                      <Send className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center">
                <div className="text-center">
                  <MessageSquare className="w-16 h-16 text-white/30 mx-auto mb-4" />
                  <p className="text-white/50">Select a conversation to start messaging</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );

  // Main Render
  if (!currentUser) {
    switch (currentView) {
      case 'login':
        return renderAuth('login');
      case 'signup':
        return renderAuth('signup');
      default:
        return renderLandingPage();
    }
  }

  switch (currentView) {
    case 'profile':
      return renderProfile();
    case 'chat':
      return renderChat();
    default:
      return renderFeed();
  }
};

export default SickoScoopApp;