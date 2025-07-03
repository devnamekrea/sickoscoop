// App.js - FIXED VERSION with Dynamic Environment Detection
import React, { useState, useRef, useEffect, useCallback } from 'react';
import { Heart, MessageCircle, Share2, Send, Image, Video, FileText, Mic, Search, Settings, X, MoreHorizontal, Flag, Bookmark, Eye, ArrowLeft, Clock, Users, Copy, ExternalLink, Twitter, Facebook, Linkedin, CheckCircle, AlertCircle } from 'lucide-react';

// Sharp SickoScoop logo with purple gradient
const SickoScoopLogo = ({ size = "default", className = "" }) => {
  const dimensions = {
    small: { width: 140, height: 36 },
    default: { width: 200, height: 48 },
    large: { width: 280, height: 64 }
  };

  const { width, height } = dimensions[size];
  
  return (
    <svg 
      width={width} 
      height={height} 
      viewBox="0 0 280 64" 
      className={className}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id="purpleTextGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#e879f9" />
          <stop offset="25%" stopColor="#c084fc" />
          <stop offset="50%" stopColor="#a78bfa" />
          <stop offset="75%" stopColor="#818cf8" />
          <stop offset="100%" stopColor="#6366f1" />
        </linearGradient>
        
        <filter id="textShadow">
          <feDropShadow dx="0" dy="2" stdDeviation="1" floodColor="#1e1b4b" floodOpacity="0.3"/>
        </filter>
      </defs>
      
      <text 
        x="140" 
        y="42" 
        fontSize="32" 
        fontWeight="700" 
        fill="url(#purpleTextGradient)"
        fontFamily="system-ui, -apple-system, 'Segoe UI', sans-serif"
        textAnchor="middle"
        filter="url(#textShadow)"
        style={{
          letterSpacing: '-0.02em',
          paintOrder: 'stroke fill'
        }}
      >
        SickoScoop
      </text>
    </svg>
  );
}; // ← IMPORTANT: Semicolon here!

// Clean SS logo for compact spaces  
const SSLogo = ({ size = "default", className = "" }) => {
  const dimensions = {
    small: { width: 60, height: 36 },
    default: { width: 80, height: 48 },
    large: { width: 100, height: 64 }
  };

  const { width, height } = dimensions[size];
  
  return (
    <svg 
      width={width} 
      height={height} 
      viewBox="0 0 100 64" 
      className={className}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id="ssGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#e879f9" />
          <stop offset="50%" stopColor="#a78bfa" />
          <stop offset="100%" stopColor="#6366f1" />
        </linearGradient>
        
        <filter id="ssTextShadow">
          <feDropShadow dx="0" dy="2" stdDeviation="1" floodColor="#1e1b4b" floodOpacity="0.4"/>
        </filter>
      </defs>
      
      <text 
        x="50" 
        y="44" 
        fontSize="36" 
        fontWeight="800" 
        fill="url(#ssGradient)"
        fontFamily="system-ui, -apple-system, 'Segoe UI', sans-serif"
        textAnchor="middle"
        filter="url(#ssTextShadow)"
        style={{
          letterSpacing: '-0.05em'
        }}
      >
        SS
      </text>
    </svg>
  );
}; // ← IMPORTANT: Semicolon here!

// Clean SS favicon
const SSFavicon = ({ size = 32, className = "" }) => {
  return (
    <svg 
      width={size} 
      height={size} 
      viewBox="0 0 64 64" 
      className={className}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id="faviconBg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#312e81" />
          <stop offset="50%" stopColor="#1e1b4b" />
          <stop offset="100%" stopColor="#0f0c29" />
        </linearGradient>
        
        <linearGradient id="faviconText" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#fbbf24" />
          <stop offset="25%" stopColor="#e879f9" />
          <stop offset="75%" stopColor="#a78bfa" />
          <stop offset="100%" stopColor="#6366f1" />
        </linearGradient>
        
        <filter id="faviconGlow">
          <feGaussianBlur stdDeviation="0.5" result="coloredBlur"/>
          <feMerge> 
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
      
      <rect 
        x="4" 
        y="4" 
        width="56" 
        height="56" 
        rx="14" 
        ry="14" 
        fill="url(#faviconBg)" 
        stroke="url(#faviconText)" 
        strokeWidth="1"
      />
      
      <text 
        x="32" 
        y="42" 
        fontSize="24" 
        fontWeight="900" 
        fill="url(#faviconText)"
        textAnchor="middle"
        fontFamily="system-ui, -apple-system, sans-serif"
        filter="url(#faviconGlow)"
        style={{
          letterSpacing: '-0.1em'
        }}
      >
        SS
      </text>
    </svg>
  );
};

const safeString = (value) => value ? String(value) : '';
const safeNumber = (value) => Number(value) || 0;

// ✅ FIXED: Dynamic API Base URL Detection
const getApiBase = () => {
  const hostname = window.location.hostname;
  const port = window.location.port;
  
  // Production detection
  if (hostname.includes('sickoscoop') || hostname.includes('netlify.app') || hostname.includes('digitalocean')) {
    return 'https://sickoscoop-backend-deo45.ondigitalocean.app/api';
  }
  
  // Development detection
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    // If frontend is on 3000, backend is on 3001
    if (port === '3000') {
      return 'http://localhost:3001/api';
    }
    // If frontend is on 3001 (same port as backend), use relative URLs
    if (port === '3001') {
      return '/api';
    }
  }
  
  // Fallback to production
  return 'https://sickoscoop-backend-deo45.ondigitalocean.app/api';
};

const API_BASE = getApiBase();

console.log('🌐 Environment Detection:', {
  hostname: window.location.hostname,
  port: window.location.port,
  apiBase: API_BASE,
  environment: API_BASE.includes('localhost') ? 'development' : 'production'
});

// Enhanced URL generation for posts
const generatePostUrl = (postId) => {
  const baseUrl = window.location.hostname === 'localhost' 
    ? 'http://localhost:3000'
    : 'https://sickoscoop.netlify.app';
  return `${baseUrl}/post/${postId}`;
};

// Enhanced timestamp function with more details
const getDetailedTimestamp = (date) => {
  const now = new Date();
  const postDate = new Date(date);
  const diffInMinutes = Math.floor((now - postDate) / (1000 * 60));
  
  if (diffInMinutes < 1) return { relative: 'Just now', absolute: postDate.toLocaleTimeString() };
  if (diffInMinutes < 60) return { 
    relative: `${diffInMinutes}m ago`, 
    absolute: postDate.toLocaleString() 
  };
  
  const diffInHours = Math.floor(diffInMinutes / 60);
  if (diffInHours < 24) return { 
    relative: `${diffInHours}h ago`, 
    absolute: postDate.toLocaleString() 
  };
  
  const diffInDays = Math.floor(diffInHours / 24);
  if (diffInDays < 7) return { 
    relative: `${diffInDays}d ago`, 
    absolute: postDate.toLocaleDateString() 
  };
  
  const diffInWeeks = Math.floor(diffInDays / 7);
  if (diffInWeeks < 4) return { 
    relative: `${diffInWeeks}w ago`, 
    absolute: postDate.toLocaleDateString() 
  };
  
  return { 
    relative: postDate.toLocaleDateString(), 
    absolute: postDate.toLocaleString() 
  };
};

// Enhanced API helper with better error handling
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

  // Remove Content-Type for FormData
  if (options.body instanceof FormData) {
    delete defaultOptions.headers['Content-Type'];
  }

  console.log('🌐 API Request:', {
    url,
    method: options.method || 'GET',
    hasToken: !!token,
    hasBody: !!options.body
  });

  try {
    const response = await fetch(url, defaultOptions);
    
    console.log('📡 API Response:', {
      url,
      status: response.status,
      statusText: response.statusText,
      ok: response.ok
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('❌ API Request Failed:', {
      url,
      error: error.message,
      stack: error.stack
    });
    throw error;
  }
};

const TermsOfServiceModal = React.memo(({ isOpen, onClose, onAccept }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-gradient-to-r from-slate-900/95 to-zinc-900/95 backdrop-blur-md rounded-2xl border border-slate-600/50 shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-6 border-b border-slate-600/30">
          <h2 className="text-2xl font-bold text-white">Terms of Service</h2>
          <button 
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>
        
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-140px)]">
          <div className="prose prose-invert prose-slate max-w-none">
            <div className="space-y-6 text-slate-300">
              <div>
                <h2 className="text-2xl font-bold text-white mb-4">Welcome to SickoScoop</h2>
                <p className="text-lg leading-relaxed">
                  The goal of this app is to stop Facebook "Are We Dating The Same Guy?" ("AWDTSG") stalkers. 
                  These losers represent yet another example of how the greatest threat to romance, dating and love 
                  is the anonymity of those in power.
                </p>
              </div>

              <section>
                <h3 className="text-xl font-semibold text-white mb-3">Terms of Transparency</h3>
                <p className="text-lg leading-relaxed">
                  Be transparent with us and we will be transparent with you. Our terms of transparency are light and reciprocity.
                </p>
              </section>

              <section>
                <h3 className="text-xl font-semibold text-white mb-3">Terms of Service</h3>
                <p className="leading-relaxed mb-4">
                  SickoScoop builds technologies and services that enable anyone, including victims of Facebook AWDTSG stalkers, 
                  to connect with each other, build communities and protect one other. These terms govern your use of SickoScoop. 
                  We abide by any and all applicable laws.
                </p>
                <p className="leading-relaxed">
                  <strong>Unlike other platforms like Facebook, Twitter, Instagram, Google, Reddit et al., we do not harvest nor sell your data.</strong> 
                  When you interact with SickoScoop, we do not exploit you. Unlike these other platforms, we do not lie to you.
                </p>
              </section>

              <section>
                <h3 className="text-xl font-semibold text-white mb-3">Money, Oil + Data</h3>
                <p className="leading-relaxed mb-4">
                  The Facebook model of "social media" claims that the surveillance they do on you and everyone you love is because 
                  they want to show you "personalized ads". This way you can better navigate the "free market". Nothing could be 
                  further from the truth. This is why Facebook <em>never</em> shows you <em>how</em> they decide what "personalized ads" they show you.
                </p>
                <p className="leading-relaxed mb-4">
                  Like those who own central banks that print our money and those who own all the industries without which we could 
                  hardly live our everyday lives, Facebook's bosses, administrators and moderators – as well as those who build and 
                  operate their algorithms and apps – remain anonymous. This is how they control and harm you. This is why you cannot 
                  protect the data coalescing about your soul in our machine-language life-world. This is what they want.
                </p>
                <p className="leading-relaxed">
                  <strong>But the solution is simple.</strong> If they cannot be honest while they interact with you, then you should not 
                  interact with them. SickoScoop is built to help you retrieve your freedom and dignity and share them with others.
                </p>
              </section>

              <section>
                <h3 className="text-xl font-semibold text-white mb-3">Privacy Policy</h3>
                <p className="leading-relaxed mb-4">
                  Opposite the Facebook model of invading your privacy while they remain anonymous, SickoScoop only interacts with 
                  your data to the extent that it can create a more transparent and safe online interaction for you as well as us. 
                  We grow together through that which military-fronts like Facebook lack: <strong>the spirit of reciprocity</strong>.
                </p>
                <p className="leading-relaxed">
                  We are a small community of humble, good people. We do not charge you to use SickoScoop. We do not show you ads. 
                  For this we would be grateful, if you could spread the word and/or donate to our cause.
                </p>
              </section>

              <section>
                <h3 className="text-xl font-semibold text-white mb-3">PDF Watermarking & Tracking</h3>
                <p className="leading-relaxed">
                  When you upload PDF documents to SickoScoop, they will be watermarked with your username and tracking information. 
                  This helps protect content creators and maintains accountability within our community. We track PDF access for 
                  security purposes and to prevent misuse of shared documents.
                </p>
              </section>

              <section>
                <h3 className="text-xl font-semibold text-white mb-3">Contact Information</h3>
                <p className="leading-relaxed">
                  If you have any questions, please contact us: 
                  <a href="mailto:admin@sickoscoop.com" className="text-blue-400 hover:text-blue-300 ml-1 underline">
                    admin@sickoscoop.com
                  </a>
                </p>
              </section>

              <div className="mt-8 p-6 bg-gradient-to-r from-blue-900/30 to-purple-900/30 rounded-lg border border-blue-500/30">
                <h4 className="text-lg font-semibold text-white mb-3">Our Mission</h4>
                <p className="text-slate-300 leading-relaxed">
                  SickoScoop is built on principles of transparency, reciprocity, and genuine human connection. 
                  We believe in creating safe spaces where people can connect without fear of stalking, harassment, 
                  or surveillance capitalism. By joining our community, you're helping build a better alternative 
                  to exploitative social media platforms.
                </p>
              </div>

              <div className="mt-6 p-4 bg-slate-800/50 rounded-lg border border-slate-600/30">
                <p className="text-sm text-slate-400">
                  <strong>By clicking "I Accept Terms of Service" below, you acknowledge that you have read, 
                  understood, and agree to be bound by these terms and our mission to stop anonymous stalkers and 
                  promote transparency in online interactions.</strong>
                </p>
              </div>
            </div>
          </div>
        </div>
        
        <div className="flex justify-end space-x-3 p-6 border-t border-slate-600/30 bg-slate-900/50">
          <button
            onClick={onClose}
            className="px-6 py-3 bg-slate-700/50 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg transition-colors border border-slate-600/50"
          >
            Cancel
          </button>
          <button
            onClick={onAccept}
            className="px-6 py-3 bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white rounded-lg transition-all duration-200 shadow-lg hover:shadow-amber-500/25 border border-amber-500/50"
          >
            I Accept Terms of Service
          </button>
        </div>
      </div>
    </div>
  );
});

// Enhanced Share Modal Component
const ShareModal = React.memo(({ post, isOpen, onClose }) => {
  const [copied, setCopied] = useState(false);
  const postUrl = generatePostUrl(post._id);
  const shareText = `Check out this post by ${post.userId?.username || 'someone'} on SickoScoop: "${post.content.substring(0, 100)}${post.content.length > 100 ? '...' : ''}"`;

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(postUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
      const textArea = document.createElement('textarea');
      textArea.value = postUrl;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleSocialShare = (platform) => {
    const encodedText = encodeURIComponent(shareText);
    const encodedUrl = encodeURIComponent(postUrl);
    
    const shareUrls = {
      twitter: `https://twitter.com/intent/tweet?text=${encodedText}&url=${encodedUrl}`,
      facebook: `https://www.facebook.com/sharer/sharer.php?u=${encodedUrl}`,
      linkedin: `https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}`,
      reddit: `https://reddit.com/submit?url=${encodedUrl}&title=${encodedText}`,
      email: `mailto:?subject=${encodeURIComponent('Check out this SickoScoop post')}&body=${encodedText}%0A%0A${encodedUrl}`
    };

    if (shareUrls[platform]) {
      window.open(shareUrls[platform], '_blank', 'width=600,height=400');
    }
  };

  const handleNativeShare = async () => {
    if (navigator.share) {
      try {
        await navigator.share({
          title: 'SickoScoop Post',
          text: shareText,
          url: postUrl,
        });
      } catch (error) {
        console.error('Error sharing:', error);
      }
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-gradient-to-r from-slate-900/95 to-zinc-900/95 backdrop-blur-md rounded-2xl border border-slate-600/50 shadow-2xl max-w-md w-full mx-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-6 border-b border-slate-600/30">
          <h3 className="text-xl font-semibold text-white">Share Post</h3>
          <button 
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        
        <div className="p-6">
          <div className="bg-slate-800/50 rounded-lg p-4 mb-6">
            <div className="flex items-center space-x-3 mb-3">
              <div className="w-8 h-8 bg-gradient-to-r from-slate-600 to-zinc-600 rounded-full flex items-center justify-center text-white font-semibold text-xs">
                {post.userId?.username?.slice(0, 2).toUpperCase() || 'UN'}
              </div>
              <span className="text-white font-medium">{post.userId?.username || 'Unknown User'}</span>
            </div>
            <p className="text-slate-300 text-sm line-clamp-3">{post.content}</p>
          </div>

          <div className="mb-6">
            <label className="block text-sm font-medium text-slate-300 mb-2">Post Link</label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={postUrl}
                readOnly
                className="flex-1 px-3 py-2 bg-black/40 border border-slate-600/50 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/50"
              />
              <button
                onClick={handleCopyLink}
                className={`px-4 py-2 rounded-lg transition-all duration-200 flex items-center space-x-2 ${
                  copied 
                    ? 'bg-green-600 text-white' 
                    : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                }`}
              >
                <Copy className="h-4 w-4" />
                <span>{copied ? 'Copied!' : 'Copy'}</span>
              </button>
            </div>
          </div>

          <div className="space-y-4">
            <label className="block text-sm font-medium text-slate-300">Share to</label>
            
            {navigator.share && (
              <button
                onClick={handleNativeShare}
                className="w-full flex items-center space-x-3 p-3 bg-slate-700/50 hover:bg-slate-700/70 rounded-lg transition-colors text-white"
              >
                <Share2 className="h-5 w-5" />
                <span>Share via device</span>
              </button>
            )}

            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => handleSocialShare('twitter')}
                className="flex items-center space-x-3 p-3 bg-blue-600/20 hover:bg-blue-600/30 rounded-lg transition-colors text-blue-400 border border-blue-600/30"
              >
                <Twitter className="h-5 w-5" />
                <span>Twitter</span>
              </button>
              
              <button
                onClick={() => handleSocialShare('facebook')}
                className="flex items-center space-x-3 p-3 bg-blue-700/20 hover:bg-blue-700/30 rounded-lg transition-colors text-blue-300 border border-blue-700/30"
              >
                <Facebook className="h-5 w-5" />
                <span>Facebook</span>
              </button>
              
              <button
                onClick={() => handleSocialShare('linkedin')}
                className="flex items-center space-x-3 p-3 bg-blue-800/20 hover:bg-blue-800/30 rounded-lg transition-colors text-blue-200 border border-blue-800/30"
              >
                <Linkedin className="h-5 w-5" />
                <span>LinkedIn</span>
              </button>
              
              <button
                onClick={() => handleSocialShare('email')}
                className="flex items-center space-x-3 p-3 bg-slate-700/20 hover:bg-slate-700/30 rounded-lg transition-colors text-slate-300 border border-slate-700/30"
              >
                <ExternalLink className="h-5 w-5" />
                <span>Email</span>
              </button>
            </div>

            <div className="pt-4 border-t border-slate-600/30">
              <button
                onClick={() => handleSocialShare('reddit')}
                className="w-full flex items-center space-x-3 p-3 bg-orange-600/20 hover:bg-orange-600/30 rounded-lg transition-colors text-orange-400 border border-orange-600/30"
              >
                <ExternalLink className="h-5 w-5" />
                <span>Share to Reddit</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
});

// Enhanced Video Player Component
const EnhancedVideoPlayer = React.memo(({ file }) => {
  const [isLoading, setIsLoading] = useState(true);
  const [hasError, setHasError] = useState(false);
  const [isPlaying, setIsPlaying] = useState(false);
  const videoRef = useRef(null);

  const handleLoadedData = () => {
    setIsLoading(false);
    setHasError(false);
  };

  const handleError = () => {
    setIsLoading(false);
    setHasError(true);
  };

  const handlePlay = () => {
    setIsPlaying(true);
  };

  const handlePause = () => {
    setIsPlaying(false);
  };

  const handleClick = (e) => {
    e.stopPropagation();
    if (videoRef.current) {
      if (isPlaying) {
        videoRef.current.pause();
      } else {
        videoRef.current.play();
      }
    }
  };

  return (
    <div className="relative w-full bg-black rounded-xl overflow-hidden">
      {isLoading && (
        <div className="absolute inset-0 flex items-center justify-center bg-slate-800/50 z-10">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-white"></div>
          <span className="ml-2 text-white text-sm">Loading video...</span>
        </div>
      )}
      
      {hasError ? (
        <div className="p-8 text-center bg-slate-800/50">
          <div className="text-red-400 mb-2">
            <Video className="h-8 w-8 mx-auto mb-2" />
            <p>Unable to load video</p>
          </div>
          <p className="text-slate-400 text-sm">{file.filename}</p>
          <a 
            href={file.url} 
            target="_blank" 
            rel="noopener noreferrer"
            className="mt-2 inline-block text-blue-400 hover:text-blue-300 text-sm underline"
            onClick={(e) => e.stopPropagation()}
          >
            Download video
          </a>
        </div>
      ) : (
        <video
          ref={videoRef}
          className="w-full h-auto max-h-96 cursor-pointer"
          onLoadedData={handleLoadedData}
          onError={handleError}
          onPlay={handlePlay}
          onPause={handlePause}
          onClick={handleClick}
          preload="metadata"
          playsInline
        >
          <source src={file.url} type={file.mimeType || file.type} />
          Your browser does not support video playback.
        </video>
      )}
      
      {!isLoading && !hasError && (
        <div className="absolute bottom-2 left-2 bg-black/60 rounded px-2 py-1 text-white text-xs">
          {file.filename}
        </div>
      )}
    </div>
  );
});

// URL Router simulation
const useSimpleRouter = () => {
  const [currentPath, setCurrentPath] = useState(window.location.pathname);
  
  useEffect(() => {
    const handlePopState = () => {
      setCurrentPath(window.location.pathname);
    };
    
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);
  
  const navigate = (path) => {
    window.history.pushState({}, '', path);
    setCurrentPath(path);
  };
  
  return { currentPath, navigate };
};

// Landing Page Component
const LandingPage = React.memo(({ 
  loginForm, 
  setLoginForm, 
  registerForm, 
  setRegisterForm, 
  showRegister, 
  setShowRegister, 
  handleLogin, 
  handleRegister, 
  loading, 
  error,
  onBrowsePublic,
  termsAccepted,
  setTermsAccepted,
  showTermsModal,
  setShowTermsModal
}) => (
  <div className="min-h-screen relative overflow-hidden border-4 border-orange-600/80">
    <div className="absolute inset-0 bg-gradient-to-br from-gray-900 via-slate-900 to-zinc-900">
      <div className="absolute inset-0 opacity-10">
        <div className="absolute top-10 left-10 w-32 h-32 bg-gradient-to-r from-purple-800 to-indigo-700 rounded-full blur-xl animate-pulse"></div>
        <div className="absolute top-40 right-20 w-24 h-24 bg-gradient-to-r from-slate-700 to-gray-600 rounded-full blur-lg animate-pulse delay-1000"></div>
        <div className="absolute bottom-20 left-1/3 w-40 h-40 bg-gradient-to-r from-zinc-800 to-slate-700 rounded-full blur-2xl animate-pulse delay-2000"></div>
      </div>
    </div>

    <div className="relative z-10 flex flex-col items-center justify-center min-h-screen p-8 text-center">
      <div className="mb-8 relative">
        <div className="text-6xl md:text-8xl font-bold bg-gradient-to-r from-slate-300 via-purple-400 to-indigo-400 bg-clip-text text-transparent">
          SickoScoop
        </div>
      </div>

      <h1 className="text-4xl md:text-6xl font-bold text-white mb-10 drop-shadow-2xl leading-none">
        <span className="whitespace-nowrap">STOP STALKERS</span>
        <br />
        <span className="text-2xl md:text-4xl block my-2">ON</span>
        <span className="bg-gradient-to-r from-orange-300 via-red-400 via-blue-400 to-indigo-400 bg-clip-text text-transparent block animate-pulse relative">
          <span className="absolute inset-0 bg-gradient-to-r from-orange-200 via-red-300 via-cyan-300 to-blue-300 bg-clip-text text-transparent blur-sm opacity-80"></span>
          <span className="absolute inset-0 bg-gradient-to-r from-amber-300 via-rose-300 via-sky-300 to-violet-300 bg-clip-text text-transparent blur-xs opacity-40"></span>
          SICKOSCOOP
        </span>
      </h1>

      <div className="mb-8 flex flex-col items-center">
        <button
          onClick={onBrowsePublic}
          className="px-8 py-3 bg-gradient-to-r from-gray-900 via-slate-800 to-black text-white text-lg font-semibold rounded-lg hover:scale-105 transform transition-all duration-300 shadow-2xl hover:shadow-amber-500/50 border-2 border-amber-500/80 hover:border-amber-400 hover:from-gray-800 hover:via-slate-700 hover:to-gray-900 backdrop-blur-md flex items-center space-x-3"
        >
          <div className="relative w-6 h-6">
            <div className="absolute inset-0 bg-gradient-to-br from-purple-400 via-indigo-500 to-violet-600 rounded-full opacity-80 blur-sm animate-pulse"></div>
            <div className="absolute inset-1 bg-gradient-to-tr from-orange-400 via-amber-500 to-red-500 rounded-full opacity-90"></div>
            <div className="absolute inset-0 bg-gradient-to-br from-cyan-400 via-blue-500 to-indigo-600 transform rotate-45 opacity-70 blur-sm"></div>
            <div className="absolute inset-1 bg-gradient-to-tr from-amber-300 via-orange-400 to-red-400 transform rotate-45 opacity-80"></div>
            <div className="absolute inset-0 bg-gradient-to-bl from-violet-400 via-purple-500 to-indigo-600 opacity-60" style={{clipPath: 'polygon(50% 10%, 10% 90%, 90% 90%)'}}></div>
            <div className="absolute inset-1 bg-gradient-to-tl from-orange-300 via-amber-400 to-yellow-400 opacity-70 animate-pulse" style={{clipPath: 'polygon(50% 15%, 15% 85%, 85% 85%)'}}></div>
          </div>
          <span>Browse Public Feed</span>
        </button>
        <p className="text-slate-400 text-sm mt-2">See what people are sharing • No account required</p>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-blue-500/20 border border-red-500/50 rounded-lg text-red-300 max-w-md">
          {error}
        </div>
      )}

      <div className="mb-8 w-full max-w-md">
        {!showRegister ? (
          <div className="space-y-4">
            <input
              type="email"
              placeholder="Email"
              value={loginForm.email}
              onChange={(e) => setLoginForm(prev => ({ ...prev, email: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
              autoComplete="email"
              className="w-full p-3 bg-black/40 border border-slate-600/50 rounded-lg text-white placeholder-slate-300 focus:outline-none focus:ring-2 focus:ring-slate-400"
            />
            <input
              type="password"
              placeholder="Password"
              value={loginForm.password}
              onChange={(e) => setLoginForm(prev => ({ ...prev, password: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
              autoComplete="current-password"
              className="w-full p-3 bg-black/40 border border-slate-600/50 rounded-lg text-white placeholder-slate-300 focus:outline-none focus:ring-2 focus:ring-slate-400"
            />
            <button
              onClick={handleLogin}
              disabled={loading}
              className="w-full px-12 py-4 bg-gradient-to-r from-gray-900 via-slate-800 to-black text-white text-xl font-semibold rounded-lg hover:scale-105 transform transition-all duration-300 shadow-2xl hover:shadow-amber-500/50 border-2 border-amber-500/80 hover:border-amber-400 hover:from-gray-800 hover:via-slate-700 hover:to-gray-900 disabled:opacity-50"
            >
              {loading ? 'Entering...' : 'Enter Sicko'}
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <input
              type="text"
              placeholder="Username"
              value={registerForm.username}
              onChange={(e) => setRegisterForm(prev => ({ ...prev, username: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && termsAccepted && handleRegister()}
              autoComplete="username"
              className="w-full p-3 bg-black/40 border border-slate-600/50 rounded-lg text-white placeholder-slate-300 focus:outline-none focus:ring-2 focus:ring-slate-400"
            />
            <input
              type="email"
              placeholder="Email"
              value={registerForm.email}
              onChange={(e) => setRegisterForm(prev => ({ ...prev, email: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && termsAccepted && handleRegister()}
              autoComplete="email"
              className="w-full p-3 bg-black/40 border border-slate-600/50 rounded-lg text-white placeholder-slate-300 focus:outline-none focus:ring-2 focus:ring-slate-400"
            />
            <input
              type="password"
              placeholder="Password"
              value={registerForm.password}
              onChange={(e) => setRegisterForm(prev => ({ ...prev, password: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && termsAccepted && handleRegister()}
              autoComplete="new-password"
              className="w-full p-3 bg-black/40 border border-slate-600/50 rounded-lg text-white placeholder-slate-300 focus:outline-none focus:ring-2 focus:ring-slate-400"
            />
            
            {/* Terms of Service Agreement */}
            <div className="space-y-3">
              <div className="flex items-start space-x-3 p-4 bg-black/20 rounded-lg border border-slate-600/30">
                <input
                  type="checkbox"
                  id="terms-checkbox"
                  checked={termsAccepted}
                  onChange={(e) => setTermsAccepted(e.target.checked)}
                  className="mt-1 w-4 h-4 text-amber-600 bg-black/40 border-slate-600 rounded focus:ring-amber-500 focus:ring-2"
                />
                <label htmlFor="terms-checkbox" className="text-slate-300 text-sm leading-relaxed">
                  I have read and agree to the{' '}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.preventDefault();
                      setShowTermsModal(true);
                    }}
                    className="text-amber-400 hover:text-amber-300 underline font-medium"
                  >
                    Terms of Service, Privacy Policy, and Terms of Transparency
                  </button>
                  {' '}including SickoScoop's mission to stop anonymous stalkers and promote genuine communication.
                </label>
              </div>
              
              {!termsAccepted && (
                <p className="text-xs text-slate-500">
                  ✓ You must accept our terms to join the fight against anonymous stalkers
                </p>
              )}
            </div>
            
            <button
              onClick={handleRegister}
              disabled={loading || !termsAccepted}
              className={`w-full px-12 py-4 text-xl font-semibold rounded-lg transition-all duration-300 shadow-2xl border-2 ${
                termsAccepted 
                  ? 'bg-gradient-to-r from-gray-900 via-slate-800 to-black text-white hover:scale-105 border-amber-500/80 hover:border-amber-400 hover:from-gray-800 hover:via-slate-700 hover:to-gray-900 hover:shadow-amber-500/50' 
                  : 'bg-slate-800/50 text-slate-500 border-slate-600/30 cursor-not-allowed'
              } disabled:opacity-50`}
            >
              {loading ? 'Creating Account...' : 'Join Sicko'}
            </button>
          </div>
        )}
        
        {/* UPDATED TOGGLE BUTTON */}
        <button
          onClick={() => {
            setShowRegister(!showRegister);
            // Reset terms acceptance when switching between login/register
            setTermsAccepted(false);
            // Clear any existing errors
            setError('');
          }}
          className="mt-4 text-slate-300 hover:text-white transition-colors"
        >
          {showRegister ? 'Already have an account? Sign in' : 'Need an account? Register'}
        </button>
      </div>

      <div className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl">
        {[
          { 
            icon: (
              <div className="relative w-12 h-12">
                <div className="absolute inset-0 bg-gradient-to-br from-purple-300 via-indigo-400 to-violet-500 rounded-full opacity-80 blur-sm"></div>
                <div className="absolute inset-1 bg-gradient-to-tr from-orange-300 via-orange-400 to-blue-500 rounded-full opacity-90 animate-pulse"></div>
                <div className="absolute inset-2 bg-gradient-to-bl from-blue-300 via-purple-400 to-indigo-500 rounded-full opacity-70"></div>
                <div className="absolute inset-3 bg-gradient-to-tl from-orange-300 via-purple-300 to-blue-400 rounded-full animate-pulse"></div>
              </div>
            ), 
            title: 'Anti-Stalker Protection', 
            desc: 'Advanced privacy controls' 
          },
          { 
            icon: (
              <div className="relative w-12 h-12">
                <div className="absolute inset-0 bg-gradient-to-br from-purple-300 via-indigo-400 to-violet-500 transform rotate-45 opacity-80 blur-sm"></div>
                <div className="absolute inset-1 bg-gradient-to-tr from-orange-300 via-orange-400 to-blue-500 transform rotate-45 opacity-90 animate-pulse"></div>
                <div className="absolute inset-2 bg-gradient-to-bl from-blue-300 via-purple-400 to-indigo-500 transform rotate-45 opacity-70"></div>
                <div className="absolute inset-3 bg-gradient-to-tl from-orange-300 via-purple-300 to-blue-400 transform rotate-45 animate-pulse"></div>
              </div>
            ), 
            title: 'Decency', 
            desc: 'No anonymous trolls' 
          },
          { 
            icon: (
              <div className="relative w-12 h-12">
                <div className="absolute inset-0 bg-gradient-to-br from-violet-400 via-purple-500 to-indigo-600 opacity-80 blur-sm" style={{clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)'}}></div>
                <div className="absolute inset-1 bg-gradient-to-tr from-orange-400 via-blue-700 to-amber-500 opacity-90 animate-pulse" style={{clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)'}}></div>
                <div className="absolute inset-2 bg-gradient-to-bl from-teal-400 via-cyan-500 to-blue-600 opacity-70" style={{clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)'}}></div>
                <div className="absolute inset-3 bg-gradient-to-tl from-blue-900 via-indigo-800 to-slate-800 animate-pulse" style={{clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)'}}></div>
              </div>
            ), 
            title: 'Genuine Community', 
            desc: 'Keeping everyone safe' 
          }
        ].map((feature, idx) => (
          <div key={idx} className="bg-black/20 backdrop-blur-md rounded-2xl p-6 border border-slate-600/30 hover:bg-black/30 transition-all duration-300">
            <div className="inline-block border-2 border-amber-500/80 rounded-lg p-3 mb-4 bg-black/30">
              {feature.icon}
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">{feature.title}</h3>
            <p className="text-slate-300">{feature.desc}</p>
          </div>
        ))}
      </div>

      {/* Copyright Notice */}
      <div className="mt-16 pt-8 border-t border-slate-600/30 w-full max-w-4xl">
        <div className="text-center">
          <p className="text-slate-400 text-sm">
            © 2025 SickoScoop. All rights reserved.
          </p>
          <p className="text-slate-500 text-xs mt-2">
            Building genuine connections through transparency and safety.
          </p>
        </div>
      </div>
    </div>

    {/* TERMS OF SERVICE MODAL - ADD AT THE END */}
    <TermsOfServiceModal 
      isOpen={showTermsModal}
      onClose={() => setShowTermsModal(false)}
      onAccept={() => {
        setTermsAccepted(true);
        setShowTermsModal(false);
      }}
    />
  </div>
));

const SettingsModal = React.memo(({ isOpen, onClose, user }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-gradient-to-r from-slate-900/95 to-zinc-900/95 backdrop-blur-md rounded-2xl border border-slate-600/50 shadow-2xl max-w-md w-full mx-4 max-h-96 overflow-hidden" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-6 border-b border-slate-600/30">
          <h3 className="text-xl font-semibold text-white">Settings & About</h3>
          <button 
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        
        <div className="p-6 overflow-y-auto max-h-80">
          <div className="space-y-6">
            {/* User Info Section */}
            {user && (
              <div className="border-b border-slate-600/30 pb-4">
                <h4 className="text-lg font-semibold text-white mb-3">Account</h4>
                <div className="flex items-center space-x-3">
                  <div className="w-12 h-12 bg-gradient-to-r from-amber-500 to-orange-600 rounded-full flex items-center justify-center text-white font-bold text-sm border-2 border-amber-500/80">
                    {user.username?.slice(0, 2).toUpperCase() || 'YU'}
                  </div>
                  <div>
                    <p className="text-white font-medium">{user.username || 'Your Username'}</p>
                    <p className="text-slate-400 text-sm">{user.email || 'your@email.com'}</p>
                  </div>
                </div>
              </div>
            )}

            {/* About Section */}
            <div className="border-b border-slate-600/30 pb-4">
              <h4 className="text-lg font-semibold text-white mb-3">About SickoScoop</h4>
              <p className="text-slate-300 text-sm mb-3">
                SickoScoop is a social platform built for genuine communication and transparency. 
                We believe in creating safe spaces where people can share without fear of stalking or harassment.
              </p>
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  <span className="text-slate-400 text-xs">Anti-Stalker Protection</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                  <span className="text-slate-400 text-xs">PDF Watermarking & Tracking</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
                  <span className="text-slate-400 text-xs">Genuine Community Building</span>
                </div>
              </div>
            </div>

            {/* Privacy & Security */}
            <div className="border-b border-slate-600/30 pb-4">
              <h4 className="text-lg font-semibold text-white mb-3">Privacy & Security</h4>
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-slate-300 text-sm">Privacy Score</span>
                  <span className="text-green-400 text-sm font-semibold">{user?.privacyScore || 94}%</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-300 text-sm">Transparency</span>
                  <span className="text-blue-400 text-sm font-semibold">{user?.transparencyScore || 98}%</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-300 text-sm">Community Score</span>
                  <span className="text-purple-400 text-sm font-semibold">{user?.communityScore || 96}%</span>
                </div>
              </div>
            </div>

            {/* Copyright */}
            <div className="text-center pt-2">
              <p className="text-slate-400 text-sm font-medium">
                © 2025 SickoScoop. All rights reserved.
              </p>
              <p className="text-slate-500 text-xs mt-1">
                Version 3.0 • Building safer social connections
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
});

// Header component
const Header = React.memo(({ 
  currentView, 
  setCurrentView, 
  apiStatus, 
  handleLogout, 
  user,
  selectedPost,
  onBackToFeed,
  navigate,
  onSettingsClick,
  fetchPublicPosts
}) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);

  return (
    <header className="bg-gradient-to-r from-gray-900 via-slate-900 to-zinc-900 shadow-2xl border-b border-amber-500/30 backdrop-blur-md relative z-50">
      <div className="container mx-auto px-4 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3 flex-shrink-0">
            {currentView === 'post' && (
              <button
                onClick={onBackToFeed}
                className="p-2 text-slate-300 hover:text-white transition-colors rounded-lg hover:bg-slate-800/50 mr-2"
                title="Back to Feed"
              >
                <ArrowLeft className="h-5 w-5" />
              </button>
            )}
            
            <button
  onClick={() => {
    navigate('/');
    if (user) {
      setCurrentView('feed');
    } else {
      setCurrentView('public');
      fetchPublicPosts();
    }
  }}
  className="flex items-center space-x-3 hover:scale-105 transition-transform"
>
  {/* Show SS favicon + full logo on desktop */}
  <div className="hidden sm:flex items-center space-x-3">
    <SSFavicon size={36} />
    <SickoScoopLogo size="small" />
  </div>
  
  {/* Show just SS logo on mobile */}
  <div className="sm:hidden">
    <SSLogo size="small" />
  </div>
</button>
            
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="md:hidden p-2 text-slate-300 hover:text-white transition-colors rounded-lg hover:bg-slate-800/50"
            >
              <div className="w-5 h-5 flex flex-col justify-center space-y-1">
                <div className={`h-0.5 bg-current transition-all duration-300 ${isMobileMenuOpen ? 'rotate-45 translate-y-1.5' : ''}`}></div>
                <div className={`h-0.5 bg-current transition-all duration-300 ${isMobileMenuOpen ? 'opacity-0' : ''}`}></div>
                <div className={`h-0.5 bg-current transition-all duration-300 ${isMobileMenuOpen ? '-rotate-45 -translate-y-1.5' : ''}`}></div>
              </div>
            </button>
          </div>

          <div className="hidden md:flex items-center space-x-3 flex-1 justify-center max-w-2xl">
            {currentView === 'post' ? (
              <div className="text-center text-slate-300">
                <span className="text-lg font-medium">Post by {selectedPost?.userId?.username || 'Unknown User'}</span>
              </div>
            ) : (
              <>
                <div className="flex space-x-3">
                  <button
                    onClick={() => {
                      navigate('/');
                      setCurrentView('feed');
                    }}
                    className={`px-4 py-2 rounded-lg border-2 transition-all duration-200 font-medium text-sm lg:text-base ${
                      currentView === 'feed' 
                        ? 'bg-slate-700 text-white border-amber-500 shadow-lg shadow-amber-500/20' 
                        : 'text-slate-300 hover:text-white border-amber-600/50 hover:border-amber-500 hover:bg-slate-800/50'
                    }`}
                  >
                    Feed
                  </button>
                  <button
                    onClick={() => {
                      navigate('/profile');
                      setCurrentView('profile');
                    }}
                    className={`px-4 py-2 rounded-lg border-2 transition-all duration-200 font-medium text-sm lg:text-base ${
                      currentView === 'profile' 
                        ? 'bg-slate-700 text-white border-amber-500 shadow-lg shadow-amber-500/20' 
                        : 'text-slate-300 hover:text-white border-amber-600/50 hover:border-amber-500 hover:bg-slate-800/50'
                    }`}
                  >
                    Profile
                  </button>
                  <button
                    onClick={() => {
                      navigate('/chat');
                      setCurrentView('chat');
                    }}
                    className={`px-4 py-2 rounded-lg border-2 transition-all duration-200 font-medium text-sm lg:text-base ${
                      currentView === 'chat' 
                        ? 'bg-slate-700 text-white border-amber-500 shadow-lg shadow-amber-500/20' 
                        : 'text-slate-300 hover:text-white border-amber-600/50 hover:border-amber-500 hover:bg-slate-800/50'
                    }`}
                  >
                    Chat
                  </button>
                </div>

                <div className="hidden lg:block relative ml-4">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Search sicko..."
                    className="w-64 xl:w-72 pl-10 pr-4 py-2 bg-black/40 border border-slate-600/60 rounded-full text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-amber-500/50 focus:border-amber-500/70 transition-all duration-200 text-sm"  
                  />
                </div>
              </>
            )}
          </div>

          <div className="flex items-center flex-shrink-0 mr-2">
            {currentView !== 'post' && (
              <button
                onClick={() => setIsSearchOpen(!isSearchOpen)}
                className="lg:hidden p-2 text-slate-300 hover:text-white transition-colors rounded-lg hover:bg-slate-800/50 mr-3"
              >
                <Search className="h-5 w-5" />
              </button>
            )}

            {user && (
              <div 
                className="w-10 h-10 rounded-full flex items-center justify-center font-bold shadow-lg transition-all duration-200 cursor-pointer hover:scale-110 hover:shadow-xl text-sm bg-gradient-to-r from-amber-500 to-orange-600 border-2 border-amber-500/80 text-white mr-3"
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              >
                {safeString(user?.username?.slice(0, 2).toUpperCase()) || 'YU'}
              </div>
            )}

            <button 
  className="p-2 text-slate-300 hover:text-white transition-colors duration-200 hover:bg-slate-800/50 rounded-lg mr-3" 
  onClick={onSettingsClick}
>
  <Settings className="h-5 w-5" />
</button>
            
            {user && (
              <button
                onClick={handleLogout}
                className="hidden sm:flex px-3 py-2 text-sm rounded-lg transition-all duration-200 hover:scale-105 bg-slate-700/40 text-slate-300 border-2 border-amber-600/40 hover:border-amber-500 hover:bg-slate-700/60 hover:text-white font-semibold"
              >
                Logout
              </button>
            )}
          </div>
        </div>

        {isSearchOpen && currentView !== 'post' && (
          <div className="mt-3 lg:hidden">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search sicko..."
                className="w-full pl-10 pr-4 py-3 bg-black/40 border border-slate-600/60 rounded-full text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-amber-500/50 focus:border-amber-500/70 transition-all duration-200"
                autoFocus
              />
            </div>
          </div>
        )}

        {isMobileMenuOpen && (
          <div className="md:hidden mt-4 pb-2 bg-black/20 rounded-xl p-4 border border-slate-600/30">
            <div className="flex flex-col space-y-3">
              {currentView === 'post' && (
                <button
                  onClick={() => {
                    onBackToFeed();
                    setIsMobileMenuOpen(false);
                  }}
                  className="px-4 py-3 rounded-lg border-2 border-amber-600/50 bg-slate-700/40 text-slate-300 hover:text-white hover:border-amber-500 hover:bg-slate-700/60 transition-all duration-200 font-medium text-left flex items-center space-x-3"
                >
                  <ArrowLeft className="h-5 w-5" />
                  <span>Back to Feed</span>
                </button>
              )}
              
              {currentView !== 'post' && (
                <>
                  <button
  onClick={() => {
    navigate('/');
    if (user) {
      setCurrentView('feed');
    } else {
      setCurrentView('public');
      fetchPublicPosts();
    }
  }}
  className={`px-4 py-2 rounded-lg border-2 transition-all duration-200 font-medium text-sm lg:text-base ${
    currentView === 'feed' || currentView === 'public'
      ? 'bg-slate-700 text-white border-amber-500 shadow-lg shadow-amber-500/20' 
      : 'text-slate-300 hover:text-white border-amber-600/50 hover:border-amber-500 hover:bg-slate-800/50'
  }`}
>
  Feed
</button>
                  
                  <button
                    onClick={() => {
                      navigate('/profile');
                      setCurrentView('profile');
                      setIsMobileMenuOpen(false);
                    }}
                    className={`px-4 py-3 rounded-lg border-2 transition-all duration-200 font-medium text-left flex items-center space-x-3 ${
                      currentView === 'profile' 
                        ? 'bg-slate-700 text-white border-amber-500 shadow-lg shadow-amber-500/20' 
                        : 'text-slate-300 hover:text-white border-amber-600/50 hover:border-amber-500 hover:bg-slate-800/50'
                    }`}
                  >
                    <span className="text-lg">👤</span>
                    <span>Profile</span>
                  </button>
                  
                  <button
                    onClick={() => {
                      navigate('/chat');
                      setCurrentView('chat');
                      setIsMobileMenuOpen(false);
                    }}
                    className={`px-4 py-3 rounded-lg border-2 transition-all duration-200 font-medium text-left flex items-center space-x-3 ${
                      currentView === 'chat' 
                        ? 'bg-slate-700 text-white border-amber-500 shadow-lg shadow-amber-500/20' 
                        : 'text-slate-300 hover:text-white border-amber-600/50 hover:border-amber-500 hover:bg-slate-800/50'
                    }`}
                  >
                    <span className="text-lg">💬</span>
                    <span>Chat</span>
                  </button>
                </>
              )}
              
              <div className="border-t border-slate-600/40 my-2"></div>
              
              {user && (
                <button
                  onClick={() => {
                    handleLogout();
                    setIsMobileMenuOpen(false);
                  }}
                  className="px-4 py-3 rounded-lg border-2 border-amber-600/40 bg-slate-700/40 text-slate-300 hover:text-white hover:border-amber-500 hover:bg-slate-700/60 transition-all duration-200 font-medium text-left flex items-center space-x-3"  
                >
                  <span className="text-lg">🚪</span>
                  <span>Logout</span>
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </header>
  );
});

// Post Creator Component with Enhanced File Upload
const PostCreator = React.memo(({ 
  user, 
  newPost, 
  setNewPost, 
  handlePost, 
  loading, 
  fileInputRef, 
  handleFileUpload 
}) => {
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [uploadProgress, setUploadProgress] = useState({});
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');

  const pdfInputRef = useRef(null);
  const audioInputRef = useRef(null);
  const videoInputRef = useRef(null);
  const photoInputRef = useRef(null);

  const FILE_LIMITS = {
    image: { max: 20 * 1024 * 1024, label: '20MB' },
    video: { max: 200 * 1024 * 1024, label: '200MB' },
    audio: { max: 50 * 1024 * 1024, label: '50MB' },
    pdf: { max: 50 * 1024 * 1024, label: '50MB' }
  };

  const validateFile = (file, type) => {
    const limit = FILE_LIMITS[type];
    if (!limit) return { valid: false, error: `Unknown file type: ${type}` };
    
    if (file.size > limit.max) {
      return { 
        valid: false, 
        error: `${type.charAt(0).toUpperCase() + type.slice(1)} files must be under ${limit.label}. Your file is ${(file.size / 1024 / 1024).toFixed(1)}MB.` 
      };
    }
    
    return { valid: true };
  };

  const handleFileSelect = async (type, files) => {
    console.log('🔄 handleFileSelect called:', type, files?.length);
    if (!files || files.length === 0) return;

    const fileArray = Array.from(files);
    setUploadError('');
    
    const allowedTypes = {
      pdf: ['application/pdf'],
      audio: ['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp3', 'audio/mp4'],
      video: ['video/mp4', 'video/webm', 'video/mpeg', 'video/quicktime', 'video/mov'],
      image: ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
    };

    const validFiles = [];
    const errors = [];

    for (const file of fileArray) {
      if (!allowedTypes[type].includes(file.type)) {
        errors.push(`${file.name}: Invalid file type. Expected ${type.toUpperCase()}.`);
        continue;
      }

      const validation = validateFile(file, type);
      if (!validation.valid) {
        errors.push(`${file.name}: ${validation.error}`);
        continue;
      }

      validFiles.push(file);
    }

    if (errors.length > 0) {
      setUploadError(errors.join('\n'));
      return;
    }

    if (validFiles.length === 0) {
      setUploadError(`Please select valid ${type} files.`);
      return;
    }

    await uploadFiles(validFiles);
  };

  const uploadFiles = async (files) => {
    console.log('🚀 uploadFiles called with:', files?.length, 'files');
    if (!files || files.length === 0) return;

    setIsUploading(true);
    setUploadError('');
    setUploadProgress({});

    const formData = new FormData();
    Array.from(files).forEach(file => {
      formData.append('files', file);
    });

    let progressInterval;

    try {
      console.log('📤 Uploading files:', files.length);
      
      const totalSize = Array.from(files).reduce((sum, file) => sum + file.size, 0);
      const totalSizeMB = (totalSize / 1024 / 1024).toFixed(1);
      const sizeLabel = `${totalSizeMB}MB`;
      
      console.log(`📊 Total upload size: ${sizeLabel}`);

      const startTime = Date.now();
      setUploadProgress({ status: 'uploading', progress: 0, totalSize: sizeLabel });

      progressInterval = setInterval(() => {
        const elapsed = Date.now() - startTime;
        const estimatedTotal = Math.max(15000, totalSize / 2000);
        const progress = Math.min(90, (elapsed / estimatedTotal) * 100);
        
        setUploadProgress(prev => ({ 
          ...prev, 
          progress: Math.round(progress),
          elapsed: Math.round(elapsed / 1000)
        }));
      }, 1500);

      // ✅ FIXED: Use the enhanced API request function
      const result = await apiRequest('/media/upload', {
        method: 'POST',
        body: formData
      });

      clearInterval(progressInterval);

      setUploadProgress({ status: 'completed', progress: 100 });

      if (result.files && Array.isArray(result.files)) {
        setUploadedFiles(prev => [...prev, ...result.files]);
        console.log('📁 Files added to state:', result.files.length);
        
        setTimeout(() => {
          setUploadProgress({});
        }, 2000);
      } else {
        throw new Error('Invalid response format from server');
      }

    } catch (error) {
      console.error('❌ Upload error:', error);
      if (progressInterval) clearInterval(progressInterval);
      
      setUploadError(`Upload failed: ${error.message}`);
      setUploadProgress({});
    } finally {
      setIsUploading(false);
    }
  };

  const removeFile = (index) => {
    setUploadedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const clearError = () => {
    setUploadError('');
  };

  const hasContent = newPost.trim() || uploadedFiles.length > 0;

  const handleSubmitPost = async () => {
    if (!hasContent) return;

    try {
      await handlePost(uploadedFiles);
      
      setUploadedFiles([]);
      
      if (pdfInputRef.current) pdfInputRef.current.value = '';
      if (audioInputRef.current) audioInputRef.current.value = '';
      if (videoInputRef.current) videoInputRef.current.value = '';
      if (photoInputRef.current) photoInputRef.current.value = '';
      
    } catch (error) {
      console.error('Post submission error:', error);
    }
  };

  const getFileIcon = (file) => {
    const icons = {
      image: { icon: <Image className="h-4 w-4" />, color: 'text-blue-400', bg: 'bg-blue-500/20' },
      video: { icon: <Video className="h-4 w-4" />, color: 'text-red-400', bg: 'bg-red-500/20' },
      audio: { icon: <Mic className="h-4 w-4" />, color: 'text-green-400', bg: 'bg-green-500/20' },
      document: { icon: <FileText className="h-4 w-4" />, color: 'text-blue-400', bg: 'bg-blue-500/20' },
      pdf: { icon: <FileText className="h-4 w-4" />, color: 'text-blue-400', bg: 'bg-blue-500/20' }
    };
    
    if (icons[file.type]) {
      return icons[file.type];
    } else if (file.mimeType === 'application/pdf') {
      return icons.pdf;
    } else {
      return icons.document;
    }
  };

  return (
    <div className="bg-gradient-to-r from-slate-900/60 to-zinc-900/60 backdrop-blur-md rounded-2xl p-6 border border-slate-600/40 mb-6">
      <div className="flex space-x-4">
        <div className="w-12 h-12 bg-gradient-to-r from-slate-600 to-zinc-600 rounded-full flex items-center justify-center text-white font-semibold">
          {safeString(user?.username?.slice(0, 2).toUpperCase()) || 'YU'}
        </div>
        <div className="flex-1">
          <textarea
            value={newPost}
            onChange={(e) => setNewPost(e.target.value)}
            placeholder="Share your thoughts..."
            className="w-full p-4 bg-black/40 border border-slate-600/50 rounded-xl text-white placeholder-slate-300 resize-none focus:outline-none focus:ring-2 focus:ring-slate-400"
            rows="3"
          />
          
          {uploadError && (
            <div className="mt-3 p-3 bg-blue-500/20 border border-red-500/50 rounded-lg">
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-2">
                  <AlertCircle className="h-4 w-4 text-red-400 mt-0.5 flex-shrink-0" />
                  <div className="text-red-300 text-sm whitespace-pre-line">{uploadError}</div>
                </div>
                <button
                  onClick={clearError}
                  className="text-red-400 hover:text-red-300 ml-2"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
          
          {uploadProgress.status && (
            <div className="mt-3 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-2">
                  {uploadProgress.status === 'completed' ? (
                    <CheckCircle className="h-4 w-4 text-green-400" />
                  ) : (
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-400"></div>
                  )}
                  <span className="text-blue-400 text-sm font-medium">
                    {uploadProgress.status === 'completed' ? 'Upload Complete!' : 'Uploading files...'}
                  </span>
                </div>
                {uploadProgress.totalSize && (
                  <span className="text-blue-300 text-xs">
                    {uploadProgress.totalSize}
                  </span>
                )}
              </div>
              
              {uploadProgress.progress !== undefined && (
                <div className="mb-2">
                  <div className="w-full bg-slate-800/50 rounded-full h-2">
                    <div 
                      className="bg-blue-400 h-2 rounded-full transition-all duration-500"
                      style={{ width: `${uploadProgress.progress}%` }}
                    ></div>
                  </div>
                  <div className="flex justify-between text-xs text-blue-300 mt-1">
                    <span>{uploadProgress.progress}% complete</span>
                    {uploadProgress.elapsed && (
                      <span>{Math.floor(uploadProgress.elapsed / 60)}:{String(uploadProgress.elapsed % 60).padStart(2, '0')} elapsed</span>
                    )}
                  </div>
                </div>
              )}
              
              {uploadProgress.status === 'uploading' && (
                <p className="text-blue-300 text-xs">
                  Large files may take several minutes to upload. Please be patient.
                </p>
              )}
            </div>
          )}
          
          {uploadedFiles.length > 0 && (
            <div className="mt-4 space-y-3">
              <h4 className="text-sm font-medium text-slate-300 flex items-center space-x-2">
                <CheckCircle className="h-4 w-4 text-green-400" />
                <span>Uploaded Files ({uploadedFiles.length})</span>
              </h4>
              <div className="grid gap-3">
                {uploadedFiles.map((file, index) => {
                  const fileStyle = getFileIcon(file);
                  return (
                    <div key={index} className="flex items-center justify-between p-3 bg-black/30 rounded-lg border border-slate-600/30">
                      <div className="flex items-center space-x-3">
                        <div className={`p-2 ${fileStyle.bg} rounded-lg ${fileStyle.color}`}>
                          {fileStyle.icon}
                        </div>
                        <div>
                          <p className="text-white font-medium text-sm">{file.filename}</p>
                          <div className="flex items-center space-x-2">
                            <p className="text-slate-400 text-xs">
                              {file.type.toUpperCase()} • {(file.size / 1024 / 1024).toFixed(1)} MB
                            </p>
                            {file.trackingId && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-500/20 text-blue-400 border border-blue-500/30">
                                🔏 Tracked
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => removeFile(index)}
                        className="p-1 text-slate-400 hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors"
                        title="Remove file"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div className="mt-2 flex justify-end">
            <button
              onClick={handleSubmitPost}
              disabled={!hasContent || loading || isUploading}
              className={`flex items-center justify-center space-x-2 px-6 py-3 rounded-lg transition-colors border-2 text-base font-semibold ${
                hasContent && !loading && !isUploading
                  ? 'bg-slate-700/60 text-slate-300 hover:bg-slate-700 border-amber-600/50 hover:border-amber-500 cursor-pointer'
                  : 'bg-slate-700/30 text-slate-500 border-amber-600/30 cursor-not-allowed opacity-50'
              }`}
            >
              <span>{loading ? 'Posting...' : isUploading ? 'Uploading...' : 'Post'}</span>
            </button>
          </div>
          
          <div className="mt-2 pt-2 border-t border-slate-600/30">
            <div className="flex flex-wrap gap-2 justify-end">
              <button 
                onClick={() => pdfInputRef.current?.click()}
                disabled={isUploading}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors border-2 text-sm ${
                  isUploading
                    ? 'bg-slate-700/20 text-slate-600 border-amber-600/20 cursor-not-allowed'
                    : 'bg-slate-700/30 text-slate-500 border-amber-600/30 opacity-50 hover:opacity-70 hover:bg-slate-700/40 hover:text-slate-400'
                }`}
                title={`PDF files up to ${FILE_LIMITS.pdf.label} (with watermarking)`}
              >
                <FileText className="h-4 w-4" />
                <span>PDF</span>
                <span className="text-xs opacity-70">({FILE_LIMITS.pdf.label})</span>
                <span className="text-xs text-blue-400">🔏</span>
              </button>
              
              <button 
                onClick={() => audioInputRef.current?.click()}
                disabled={isUploading}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors border-2 text-sm ${
                  isUploading
                    ? 'bg-slate-700/20 text-slate-600 border-amber-600/20 cursor-not-allowed'
                    : 'bg-slate-700/30 text-slate-500 border-amber-600/30 opacity-50 hover:opacity-70 hover:bg-slate-700/40 hover:text-slate-400'
                }`}
                title={`Audio files up to ${FILE_LIMITS.audio.label}`}
              >
                <Mic className="h-4 w-4" />
                <span>Audio</span>
                <span className="text-xs opacity-70">({FILE_LIMITS.audio.label})</span>
              </button>
              
              <button 
                onClick={() => videoInputRef.current?.click()}
                disabled={isUploading}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors border-2 text-sm ${
                  isUploading
                    ? 'bg-slate-700/20 text-slate-600 border-amber-600/20 cursor-not-allowed'
                    : 'bg-slate-700/30 text-slate-500 border-amber-600/30 opacity-50 hover:opacity-70 hover:bg-slate-700/40 hover:text-slate-400'
                }`}
                title={`Video files up to ${FILE_LIMITS.video.label}`}
              >
                <Video className="h-4 w-4" />
                <span>Video</span>
                <span className="text-xs opacity-70">({FILE_LIMITS.video.label})</span>
              </button>
              
              <button
                onClick={() => photoInputRef.current?.click()}
                disabled={isUploading}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors border-2 text-sm ${
                  isUploading
                    ? 'bg-slate-700/20 text-slate-600 border-amber-600/20 cursor-not-allowed'
                    : 'bg-slate-700/30 text-slate-500 border-amber-600/30 opacity-50 hover:opacity-70 hover:bg-slate-700/40 hover:text-slate-400'
                }`}
                title={`Image files up to ${FILE_LIMITS.image.label}`}
              >
                <Image className="h-4 w-4" />
                <span>Photo</span>
                <span className="text-xs opacity-70">({FILE_LIMITS.image.label})</span>
              </button>
            </div>
          </div>
        </div>
      </div>
      
      <input
        ref={pdfInputRef}
        type="file"
        accept=".pdf"
        multiple
        onChange={(e) => {
          console.log('📁 PDF files selected:', e.target.files.length);
          handleFileSelect('pdf', e.target.files);
        }}
        className="hidden"
      />
      <input
        ref={audioInputRef}
        type="file"
        accept="audio/*"
        multiple
        onChange={(e) => {
          console.log('🎵 Audio files selected:', e.target.files.length);
          handleFileSelect('audio', e.target.files);
        }}
        className="hidden"
      />
      <input
        ref={videoInputRef}
        type="file"
        accept="video/*"
        multiple
        onChange={(e) => {
          console.log('📹 Video files selected:', e.target.files.length);
          handleFileSelect('video', e.target.files);
        }}
        className="hidden"
      />
      <input
        ref={photoInputRef}
        type="file"
        accept="image/*"
        multiple
        onChange={(e) => {
          console.log('📸 Photo files selected:', e.target.files.length);
          handleFileSelect('image', e.target.files);
        }}
        className="hidden"
      />
      
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept="image/*,video/*,audio/*,.pdf"
        onChange={(e) => uploadFiles(e.target.files)}
        className="hidden"
      />
    </div>
  );
});

// Enhanced Post Component
const Post = React.memo(({ 
  post, 
  user, 
  handleLike, 
  handleComment, 
  handleShare, 
  isPublicView = false, 
  onLoginPrompt,
  onPostClick,
  isDetailView = false,
  navigate
}) => {
  const [showComments, setShowComments] = useState(isDetailView);
  const [commentText, setCommentText] = useState('');
  const [showShareModal, setShowShareModal] = useState(false);
  const [showMoreMenu, setShowMoreMenu] = useState(false);
  const [showWhoLiked, setShowWhoLiked] = useState(false);
  const [isLiking, setIsLiking] = useState(false);
  const commentInputRef = useRef(null);

  const timestamp = getDetailedTimestamp(post.createdAt);

  useEffect(() => {
    if (post.mediaFiles && post.mediaFiles.length > 0) {
      console.log('🔍 POST DEBUGGING - Post has media files:', post.mediaFiles);
      post.mediaFiles.forEach((file, index) => {
        console.log(`📄 File ${index} details:`, {
          type: file.type,
          mimeType: file.mimeType,
          filename: file.filename,
          originalName: file.originalName,
          url: file.url,
          size: file.size,
          trackingId: file.trackingId,
          trackingUrl: file.trackingUrl,
          fullFile: file
        });
      });
    }
  }, [post.mediaFiles]);

  const detectFileType = (file) => {
    console.log('🎯 Detecting file type for:', file);
    
    const isPDF = 
      file.type === 'document' ||
      file.type === 'pdf' ||
      file.mimeType === 'application/pdf' ||
      (file.filename && file.filename.toLowerCase().endsWith('.pdf')) ||
      (file.originalName && file.originalName.toLowerCase().endsWith('.pdf'));
    
    console.log('📄 PDF detection result:', {
      isPDF,
      reasons: {
        typeIsDocument: file.type === 'document',
        typeIsPdf: file.type === 'pdf', 
        mimeTypeIsPdf: file.mimeType === 'application/pdf',
        filenameEndsPdf: file.filename && file.filename.toLowerCase().endsWith('.pdf'),
        originalNameEndsPdf: file.originalName && file.originalName.toLowerCase().endsWith('.pdf')
      },
      trackingId: file.trackingId,
      trackingUrl: file.trackingUrl
    });
    
    if (isPDF) {
      return {
        category: 'pdf',
        displayName: 'PDF Document',
        icon: '📄',
        bgColor: 'bg-blue-500/20',
        textColor: 'text-blue-400',
        borderColor: 'border-blue-500/40',
        hoverBgColor: 'hover:bg-blue-500/30',
        hoverTextColor: 'hover:text-blue-300',
        hoverBorderColor: 'hover:border-blue-500/60',
        isTracked: !!file.trackingId
      };
    }
    
    if (file.type === 'image' || (file.mimeType && file.mimeType.startsWith('image/'))) {
      return {
        category: 'image',
        displayName: 'Image',
        icon: '🖼️',
        bgColor: 'bg-blue-500/20',
        textColor: 'text-blue-400',
        borderColor: 'border-blue-500/40'
      };
    }
    
    if (file.type === 'video' || (file.mimeType && file.mimeType.startsWith('video/'))) {
      return {
        category: 'video',
        displayName: 'Video',
        icon: '🎬',
        bgColor: 'bg-purple-500/20',
        textColor: 'text-purple-400',
        borderColor: 'border-purple-500/40'
      };
    }
    
    if (file.type === 'audio' || (file.mimeType && file.mimeType.startsWith('audio/'))) {
      return {
        category: 'audio',
        displayName: 'Audio',
        icon: '🎵',
        bgColor: 'bg-green-500/20',
        textColor: 'text-green-400',
        borderColor: 'border-green-500/40'
      };
    }
    
    console.warn('⚠️ Unknown file type, using default:', file);
    return {
      category: 'document',
      displayName: 'Document',
      icon: '📎',
      bgColor: 'bg-orange-500/20',
      textColor: 'text-orange-400',
      borderColor: 'border-orange-500/40'
    };
  };

  const handleLikeClick = async () => {
    if (isPublicView) {
      onLoginPrompt?.();
      return;
    }
    
    setIsLiking(true);
    try {
      await handleLike(post._id);
    } finally {
      setTimeout(() => setIsLiking(false), 300);
    }
  };

  const handleCommentSubmit = () => {
    if (!commentText.trim()) return;
    
    if (isPublicView) {
      onLoginPrompt?.();
      return;
    }
    
    handleComment?.(post._id, commentText);
    setCommentText('');
  };

  const handleShareClick = () => {
    if (isPublicView) {
      onLoginPrompt?.();
      return;
    }
    setShowShareModal(true);
  };

  const handleWhoLikedClick = () => {
    if (isPublicView) {
      onLoginPrompt?.();
      return;
    }
    setShowWhoLiked(true);
  };

  const handlePostContentClick = (e) => {
    if (e.target.closest('button') || 
        e.target.closest('input') || 
        e.target.closest('a') ||
        e.target.closest('.post-action-button') ||
        showShareModal || 
        showMoreMenu || 
        showWhoLiked ||
        isDetailView) {
      return;
    }

    if (isPublicView) {
      onLoginPrompt?.();
      return;
    }

    if (navigate) {
      navigate(`/post/${post._id}`);
    }
    onPostClick?.(post);
  };

  const isLiked = !isPublicView && post.likes?.some(like => 
    (typeof like === 'string' ? like : like.user || like._id) === (user?._id || user?.id)
  );

  const likeCount = post.likes?.length || 0;
  const commentCount = post.comments?.length || 0;

  const usersWhoLiked = React.useMemo(() => {
    if (!post.likes || post.likes.length === 0) return [];
    
    return post.likes.map((like, index) => {
      if (typeof like === 'string') {
        return {
          _id: like,
          username: `User ${index + 1}`,
          avatar: '👤',
          verified: false
        };
      } else if (like.user) {
        return {
          _id: like.user._id || like.user,
          username: like.user.username || `User ${index + 1}`,
          avatar: like.user.avatar || '👤',
          verified: like.user.verified || false
        };
      } else {
        return {
          _id: like._id || `user-${index}`,
          username: like.username || `User ${index + 1}`,
          avatar: like.avatar || '👤',
          verified: like.verified || false
        };
      }
    });
  }, [post.likes]);

  const handlePDFClick = async (file) => {
    if (file.trackingId) {
      try {
        const trackingUrl = file.trackingUrl || `${API_BASE}/track/${file.trackingId}`;
        await apiRequest(`/track/${file.trackingId}`, {
          method: 'GET'
        });
        console.log('📊 PDF access tracked:', file.trackingId);
      } catch (error) {
        console.error('Failed to track PDF access:', error);
      }
    }
  };

  return (
    <>
      <div 
        className={`bg-gradient-to-r from-slate-900/40 to-zinc-900/40 backdrop-blur-md rounded-2xl p-6 border border-slate-600/30 mb-6 transition-all duration-300 group ${
          !isDetailView && !isPublicView ? 'hover:border-slate-500/50 cursor-pointer hover:bg-slate-800/30' : ''
        }`}
        onClick={handlePostContentClick}
      >
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-start space-x-4">
            <div className="w-12 h-12 bg-gradient-to-r from-slate-600 to-zinc-600 rounded-full flex items-center justify-center text-white font-semibold text-sm shadow-lg">
              {post.userId?.username?.slice(0, 2).toUpperCase() || 'UN'}
            </div>
            
            <div className="flex-1">
              <div className="flex items-center space-x-2 mb-1">
                <span className="font-semibold text-white hover:text-slate-200 cursor-pointer">
                  {post.userId?.username || 'Unknown User'}
                </span>
                {post.userId?.verified && (
                  <div className="w-5 h-5 bg-gradient-to-r from-blue-500 to-indigo-600 rounded-full flex items-center justify-center">
                    <span className="text-white text-xs">✓</span>
                  </div>
                )}
                <span className="text-slate-400 text-sm">•</span>
                <span 
                  className="text-slate-400 text-sm hover:text-slate-300 cursor-pointer flex items-center space-x-1 group/timestamp" 
                  title={timestamp.absolute}
                >
                  <Clock className="h-3 w-3" />
                  <span className="group-hover/timestamp:hidden">{timestamp.relative}</span>
                  <span className="hidden group-hover/timestamp:inline text-xs">{timestamp.absolute}</span>
                </span>
              </div>
              
              {post.userId?.transparencyScore && (
                <div className="flex items-center space-x-1">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  <span className="text-xs text-slate-500">
                    {post.userId.transparencyScore}% transparency
                  </span>
                </div>
              )}
            </div>
          </div>

          <div className="relative">
            <button 
              onClick={(e) => {
                e.stopPropagation();
                setShowMoreMenu(!showMoreMenu);
              }}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors opacity-0 group-hover:opacity-100 post-action-button"
            >
              <MoreHorizontal className="h-5 w-5" />
            </button>
            
            {showMoreMenu && (
              <div className="absolute right-0 top-10 bg-slate-800/90 backdrop-blur-md rounded-xl border border-slate-600/50 shadow-xl z-10 min-w-48">
                <button 
                  onClick={(e) => {
                    e.stopPropagation();
                    navigator.clipboard.writeText(generatePostUrl(post._id));
                    setShowMoreMenu(false);
                  }}
                  className="w-full px-4 py-3 text-left text-slate-300 hover:text-white hover:bg-slate-700/50 rounded-t-xl transition-colors flex items-center space-x-2"
                >
                  <Copy className="h-4 w-4" />
                  <span>Copy Link</span>
                </button>
                <button 
                  onClick={(e) => e.stopPropagation()}
                  className="w-full px-4 py-3 text-left text-slate-300 hover:text-white hover:bg-slate-700/50 transition-colors flex items-center space-x-2"
                >
                  <Bookmark className="h-4 w-4" />
                  <span>Save Post</span>
                </button>
                {!isDetailView && (
                  <button 
                    onClick={(e) => {
                      e.stopPropagation();
                      if (navigate) navigate(`/post/${post._id}`);
                      onPostClick?.(post);
                      setShowMoreMenu(false);
                    }}
                    className="w-full px-4 py-3 text-left text-slate-300 hover:text-white hover:bg-slate-700/50 transition-colors flex items-center space-x-2"
                  >
                    <Eye className="h-4 w-4" />
                    <span>View Post</span>
                  </button>
                )}
                <button 
                  onClick={(e) => e.stopPropagation()}
                  className="w-full px-4 py-3 text-left text-slate-300 hover:text-white hover:bg-slate-700/50 rounded-b-xl transition-colors flex items-center space-x-2"
                >
                  <Flag className="h-4 w-4" />
                  <span>Report</span>
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="mb-4">
          <p className="text-slate-200 leading-relaxed whitespace-pre-wrap">
            {post.content}
          </p>
        </div>

        {post.mediaFiles && post.mediaFiles.length > 0 && (
          <div className="mb-4 space-y-4">
            <div className="text-sm text-slate-300 mb-3 flex items-center space-x-2">
              <span className="text-xl">📎</span>
              <span className="font-medium">
                {post.mediaFiles.length} attachment{post.mediaFiles.length !== 1 ? 's' : ''}
              </span>
              <span className="text-slate-500">• Click to download or view</span>
            </div>
            
            {post.mediaFiles.map((file, idx) => {
              const fileType = detectFileType(file);
              console.log(`🎨 Rendering file ${idx}:`, { file, fileType });
              
              return (
                <div key={idx} className={`rounded-xl overflow-hidden border-2 ${fileType.borderColor} ${fileType.bgColor} p-1`}>
                  
                  {fileType.category === 'image' && (
                    <div className="p-3">
                      <img 
                        src={file.url} 
                        alt="Post media" 
                        className="w-full h-auto max-h-96 object-cover hover:scale-105 transition-transform duration-300 cursor-pointer rounded-lg" 
                        onClick={(e) => e.stopPropagation()}
                        onError={(e) => {
                          console.error('❌ Image failed to load:', file.url);
                          e.target.style.display = 'none';
                        }}
                      />
                    </div>
                  )}
                  
                  {fileType.category === 'video' && (
                    <div className="p-3">
                      <EnhancedVideoPlayer file={file} />
                    </div>
                  )}
                  
                  {fileType.category === 'audio' && (
                    <div className="p-4">
                      <div className="flex items-center space-x-3 mb-3">
                        <div className={`w-12 h-12 ${fileType.bgColor} rounded-lg flex items-center justify-center text-2xl border ${fileType.borderColor}`}>
                          {fileType.icon}
                        </div>
                        <div>
                          <p className="text-white font-medium">{file.filename || file.originalName || 'Audio File'}</p>
                          <p className="text-slate-400 text-sm">
                            {fileType.displayName} • {(file.size / 1024 / 1024).toFixed(1)} MB
                          </p>
                        </div>
                      </div>
                      <audio controls className="w-full" onClick={(e) => e.stopPropagation()}>
                        <source src={file.url} />
                        Your browser does not support audio playback.
                      </audio>
                    </div>
                  )}
                  
                  {fileType.category === 'pdf' && (
                    <div className={`p-5 ${fileType.bgColor} rounded-xl`} onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center space-x-4">
                        <div className={`w-16 h-16 ${fileType.bgColor} rounded-xl flex items-center justify-center border-2 ${fileType.borderColor} shadow-lg relative`}>
                          <span className="text-3xl">{fileType.icon}</span>
                          {fileType.isTracked && (
                            <div className="absolute -top-1 -right-1 w-4 h-4 bg-blue-500 rounded-full flex items-center justify-center">
                              <span className="text-white text-xs">🔏</span>
                            </div>
                          )}
                        </div>
                        
                        <div className="flex-1">
                          <h3 className="text-white font-bold text-lg mb-1">
                            {file.filename || file.originalName || 'PDF Document'}
                          </h3>
                          <p className={`${fileType.textColor} text-sm font-medium mb-1 flex items-center space-x-2`}>
                            <span>📄 {fileType.displayName}</span>
                            {fileType.isTracked && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-500/20 text-blue-400 border border-blue-500/30">
                                🔏 Watermarked & Tracked
                              </span>
                            )}
                          </p>
                          <p className="text-slate-400 text-sm">
                            {(file.size / 1024 / 1024).toFixed(1)} MB
                            {file.mimeType && ` • ${file.mimeType}`}
                            {file.trackingId && (
                              <span className="block text-xs mt-1 text-blue-400">
                                Tracking ID: {file.trackingId.substring(0, 8)}...
                              </span>
                            )}
                          </p>
                        </div>
                        
                        <div className="flex flex-col space-y-2">
                          <a 
                            href={file.url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className={`px-4 py-2 ${fileType.bgColor} ${fileType.hoverBgColor} ${fileType.textColor} ${fileType.hoverTextColor} rounded-lg transition-all duration-200 text-sm font-medium border-2 ${fileType.borderColor} ${fileType.hoverBorderColor} flex items-center space-x-2 hover:scale-105 transform`}
                            onClick={(e) => {
                              e.stopPropagation();
                              handlePDFClick(file);
                              console.log('🔗 Opening PDF:', file.url);
                            }}
                          >
                            <ExternalLink className="h-4 w-4" />
                            <span>View PDF</span>
                          </a>
                          
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              navigator.clipboard.writeText(file.url);
                              console.log('📋 PDF URL copied:', file.url);
                            }}
                            className="px-3 py-1 bg-slate-700/50 hover:bg-slate-700 text-slate-300 hover:text-white rounded-md transition-colors text-xs flex items-center space-x-1"
                          >
                            <Copy className="h-3 w-3" />
                            <span>Copy Link</span>
                          </button>
                        </div>
                      </div>
                      
                      <div className="mt-3 pt-3 border-t border-blue-500/20">
                        <p className="text-slate-400 text-xs">
                          📥 Uploaded {new Date(post.createdAt).toLocaleDateString()} • Click "View PDF" to open in new tab
                          {fileType.isTracked && (
                            <span className="block mt-1 text-blue-400">
                              🔏 This PDF is watermarked and tracked for security purposes
                            </span>
                          )}
                        </p>
                      </div>
                    </div>
                  )}
                  
                  {fileType.category === 'document' && (
                    <div className="p-4">
                      <div className="flex items-center space-x-3">
                        <div className={`w-12 h-12 ${fileType.bgColor} rounded-lg flex items-center justify-center text-xl border ${fileType.borderColor}`}>
                          {fileType.icon}
                        </div>
                        <div className="flex-1">
                          <p className="text-white font-medium">{file.filename || file.originalName || 'Document'}</p>
                          <p className="text-slate-400 text-sm">
                            {fileType.displayName} • {(file.size / 1024 / 1024).toFixed(1)} MB
                          </p>
                        </div>
                        <a 
                          href={file.url} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className={`px-3 py-2 ${fileType.bgColor} hover:bg-orange-500/30 ${fileType.textColor} hover:text-orange-300 rounded-lg transition-colors text-sm font-medium border ${fileType.borderColor} hover:border-orange-500/50`}
                          onClick={(e) => e.stopPropagation()}
                        >
                          View File
                        </a>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {(likeCount > 0 || commentCount > 0) && (
          <div className="flex items-center justify-between text-slate-400 text-sm mb-3 pb-3 border-b border-slate-600/30">
            <div className="flex items-center space-x-4">
              {likeCount > 0 && (
                <button 
                  onClick={(e) => {
                    e.stopPropagation();
                    handleWhoLikedClick();
                  }}
                  className="flex items-center space-x-1 hover:text-slate-300 transition-colors cursor-pointer group post-action-button"
                  title={isPublicView ? "Sign up to see who liked this" : "See who liked this post"}
                >
                  <div className="flex -space-x-1">
                    <div className="w-5 h-5 bg-gradient-to-r from-red-500 to-pink-500 rounded-full flex items-center justify-center border border-slate-800 group-hover:scale-110 transition-transform">
                      <Heart className="h-3 w-3 text-white" fill="white" />
                    </div>
                  </div>
                  <span className="hover:underline">{likeCount} {likeCount === 1 ? 'like' : 'likes'}</span>
                  {isPublicView && (
                    <span className="text-xs text-slate-500 ml-1">🔒</span>
                  )}
                </button>
              )}
              {commentCount > 0 && (
                <div className="flex items-center space-x-1">
                  <Users className="h-4 w-4" />
                  <span>{commentCount} {commentCount === 1 ? 'comment' : 'comments'}</span>
                </div>
              )}
            </div>
            <div className="flex items-center space-x-1">
              <Eye className="h-4 w-4" />
              <span>{Math.floor(Math.random() * 50) + 20} views</span>
            </div>
          </div>
        )}

        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-1">
            <button 
              onClick={(e) => {
                e.stopPropagation();
                handleLikeClick();
              }}
              className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-all duration-200 post-action-button ${
                isLiked 
                  ? 'text-red-400 bg-red-500/10 hover:bg-blue-500/20' 
                  : 'text-slate-400 hover:text-red-400 hover:bg-red-500/10'
              } ${isLiking ? 'scale-110' : ''}`}
              title={isPublicView ? "Sign up to like posts" : "Like this post"}
            >
              <Heart 
                className={`h-5 w-5 transition-all duration-200 ${isLiking ? 'scale-125' : ''}`} 
                fill={isLiked ? 'currentColor' : 'none'} 
              />
              <span className="font-medium">{likeCount || 'Like'}</span>
            </button>

            <button 
              onClick={(e) => {
                e.stopPropagation();
                if (isPublicView) {
                  onLoginPrompt?.();
                } else {
                  setShowComments(!showComments);
                  setTimeout(() => commentInputRef.current?.focus(), 100);
                }
              }}
              className="flex items-center space-x-2 px-3 py-2 rounded-lg text-slate-400 hover:text-indigo-400 hover:bg-indigo-500/10 transition-all duration-200 post-action-button"
              title={isPublicView ? "Sign up to comment" : "Comment on this post"}
            >
              <MessageCircle className="h-5 w-5" />
              <span className="font-medium">{commentCount || 'Comment'}</span>
            </button>

            <div className="relative">
              <button 
                onClick={(e) => {
                  e.stopPropagation();
                  handleShareClick();
                }}
                className="flex items-center space-x-2 px-3 py-2 rounded-lg text-slate-400 hover:text-green-400 hover:bg-green-500/10 transition-all duration-200 post-action-button"
                title={isPublicView ? "Sign up to share" : "Share this post"}
              >
                <Share2 className="h-5 w-5" />
                <span className="font-medium">Share</span>
              </button>
            </div>
          </div>

          {!isDetailView && !isPublicView && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                if (navigate) navigate(`/post/${post._id}`);
                onPostClick?.(post);
              }}
              className="text-xs text-slate-500 hover:text-slate-400 transition-colors post-action-button flex items-center space-x-1"
            >
              <Eye className="h-3 w-3" />
              <span>View Post</span>
            </button>
          )}

          {isPublicView && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onLoginPrompt();
              }}
              className="text-xs text-slate-500 hover:text-slate-400 transition-colors post-action-button"
            >
              Join to interact →
            </button>
          )}
        </div>

        {showComments && !isPublicView && (
          <div className="mt-4 pt-4 border-t border-slate-600/30 space-y-4">
            <div className="flex space-x-3">
              <div className="w-8 h-8 bg-gradient-to-r from-slate-600 to-zinc-600 rounded-full flex items-center justify-center text-white font-semibold text-xs">
                {safeString(user?.username?.slice(0, 2).toUpperCase()) || 'YU'}
              </div>
              <div className="flex-1">
                <div className="flex space-x-2">
                  <input
                    ref={commentInputRef}
                    type="text"
                    value={commentText}
                    onChange={(e) => setCommentText(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleCommentSubmit()}
                    onClick={(e) => e.stopPropagation()}
                    placeholder="Write a comment..."
                    className="flex-1 px-4 py-2 bg-black/40 border border-slate-600/50 rounded-full text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-400 focus:border-slate-400"
                  />
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleCommentSubmit();
                    }}
                    disabled={!commentText.trim()}
                    className="px-4 py-2 bg-gradient-to-r from-slate-700 to-zinc-700 text-white rounded-full hover:scale-105 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed post-action-button"
                  >
                    <Send className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>

            {post.comments && post.comments.length > 0 && (
              <div className="space-y-3">
                {post.comments.map((comment, idx) => (
                  <div key={idx} className="flex space-x-3">
                    <div className="w-8 h-8 bg-gradient-to-r from-slate-600 to-zinc-600 rounded-full flex items-center justify-center text-white font-semibold text-xs">
                      {safeString(user?.username?.slice(0, 2).toUpperCase()) || comment.author?.slice(0, 2).toUpperCase() || 'UN'}
                    </div>
                    <div className="flex-1">
                      <div className="bg-slate-800/50 rounded-2xl px-4 py-2">
                        <div className="flex items-center space-x-2 mb-1">
                          <span className="font-medium text-white text-sm">
                            {safeString(user?.username)}
                          </span>
                          <span className="text-slate-500 text-xs">
                            {getDetailedTimestamp(comment.createdAt || new Date()).relative}
                          </span>
                        </div>
                        <p className="text-slate-200 text-sm">{comment.content}</p>
                      </div>
                      <div className="flex items-center space-x-4 mt-1 px-4">
                        <button 
                          onClick={(e) => e.stopPropagation()}
                          className="text-xs text-slate-500 hover:text-slate-400 transition-colors post-action-button"
                        >
                          Like
                        </button>
                        <button 
                          onClick={(e) => e.stopPropagation()}
                          className="text-xs text-slate-500 hover:text-slate-400 transition-colors post-action-button"
                        >
                          Reply
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {(showMoreMenu) && (
          <div 
            className="fixed inset-0 z-0" 
            onClick={(e) => {
              e.stopPropagation();
              setShowMoreMenu(false);
            }}
          />
        )}
      </div>

      <ShareModal 
        post={post}
        isOpen={showShareModal}
        onClose={() => setShowShareModal(false)}
      />

      {showWhoLiked && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setShowWhoLiked(false)}>
          <div className="bg-gradient-to-r from-slate-900/95 to-zinc-900/95 backdrop-blur-md rounded-2xl border border-slate-600/50 shadow-2xl max-w-md w-full mx-4 max-h-96 overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-6 border-b border-slate-600/30">
              <h3 className="text-xl font-semibold text-white">Liked by</h3>
              <button 
                onClick={() => setShowWhoLiked(false)}
                className="p-2 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            
            <div className="p-4 overflow-y-auto max-h-80">
              {usersWhoLiked.length === 0 ? (
                <div className="text-center text-slate-400 py-8">
                  <Heart className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p>No likes yet</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {usersWhoLiked.map((likeUser, index) => (
                    <div key={index} className="flex items-center space-x-3 p-3 rounded-xl hover:bg-slate-800/30 transition-colors cursor-pointer">
                      <div className="w-10 h-10 bg-gradient-to-r from-slate-600 to-zinc-600 rounded-full flex items-center justify-center text-white font-semibold text-sm shadow-lg">
                        {likeUser.username?.slice(0, 2).toUpperCase() || likeUser.avatar || '👤'}
                      </div>
                      
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-medium text-white">{likeUser.username}</span>
                          {likeUser.verified && (
                            <div className="w-4 h-4 bg-gradient-to-r from-blue-500 to-indigo-600 rounded-full flex items-center justify-center">
                              <span className="text-white text-xs">✓</span>
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div className="text-red-400">
                        <Heart className="h-5 w-5" fill="currentColor" />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
});

// ✅ MAIN APP COMPONENT - Enhanced with Better State Management  
export default function App() {
  const { currentPath, navigate } = useSimpleRouter();
  const [user, setUser] = useState(null);
  const [posts, setPosts] = useState([]);
  const [publicPosts, setPublicPosts] = useState([]);
  const [currentView, setCurrentView] = useState('landing');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [newPost, setNewPost] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedPost, setSelectedPost] = useState(null);
  const [apiStatus, setApiStatus] = useState('checking');
  const [showSettingsModal, setShowSettingsModal] = useState(false);

  // Login/Register forms
  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const [registerForm, setRegisterForm] = useState({ username: '', email: '', password: '' });
  const [showRegister, setShowRegister] = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [showTermsModal, setShowTermsModal] = useState(false);

  const fileInputRef = useRef(null);

  // Check authentication on mount
  useEffect(() => {
    const token = localStorage.getItem('authToken');
    const userData = localStorage.getItem('userData');
    
    if (token && userData) {
      try {
        const parsedUser = JSON.parse(userData);
        setUser(parsedUser);
        setIsLoggedIn(true);
        setCurrentView('feed');
        checkApiStatus();
        fetchPosts();
      } catch (error) {
        console.error('Error parsing user data:', error);
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
      }
    } else {
      setCurrentView('landing');
    }
  }, []);

  const checkApiStatus = async () => {
    try {
      const data = await apiRequest('/health');
      setApiStatus(data.status === 'OK' ? 'online' : 'offline');
    } catch (error) {
      console.error('API health check failed:', error);
      setApiStatus('offline');
    }
  };

  // ✅ ENHANCED: Authenticated posts fetch
  const fetchPosts = async () => {
    try {
      const data = await apiRequest('/posts');
      setPosts(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error fetching posts:', error);
      setPosts([]);
    }
  };

  // ✅ ENHANCED: Public posts fetch function
  const fetchPublicPosts = async () => {
    try {
      console.log('🔄 Fetching public posts from:', `${API_BASE}/posts/public`);
      const data = await apiRequest('/posts/public');
      console.log('✅ Public posts fetched successfully:', data.length, 'posts');
      setPublicPosts(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('❌ Error fetching public posts:', error);
      setPublicPosts([]);
    }
  };

  const handleLogin = async () => {
    if (!loginForm.email || !loginForm.password) {
      setError('Please fill in all fields');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const data = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify(loginForm)
      });

      localStorage.setItem('authToken', data.token);
      localStorage.setItem('userData', JSON.stringify(data.user));
      setUser(data.user);
      setIsLoggedIn(true);
      setCurrentView('feed');
      setLoginForm({ email: '', password: '' });
      await fetchPosts();
    } catch (error) {
      console.error('Login error:', error);
      setError(error.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
  if (!registerForm.username || !registerForm.email || !registerForm.password) {
    setError('Please fill in all fields');
    return;
  }

  // Check if terms are accepted
  if (!termsAccepted) {
    setError('You must accept the Terms of Service to create an account');
    return;
  }

  setLoading(true);
  setError('');

  try {
    const data = await apiRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify(registerForm)
    });

    localStorage.setItem('authToken', data.token);
    localStorage.setItem('userData', JSON.stringify(data.user));
    setUser(data.user);
    setIsLoggedIn(true);
    setCurrentView('feed');
    setRegisterForm({ username: '', email: '', password: '' });
    setTermsAccepted(false); // Reset terms for next time
    await fetchPosts();
  } catch (error) {
    console.error('Registration error:', error);
    setError(error.message || 'Registration failed');
  } finally {
    setLoading(false);
  }
};

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('userData');
    setUser(null);
    setIsLoggedIn(false);
    setCurrentView('landing');
    setPosts([]);
    setPublicPosts([]);
    navigate('/');
  };

const handleSettingsClick = () => {
  setShowSettingsModal(true);
};

  const handlePost = async (uploadedFiles = []) => {
    if (!newPost.trim() && uploadedFiles.length === 0) return;

    setLoading(true);
    try {
      await apiRequest('/posts', {
        method: 'POST',
        body: JSON.stringify({
          content: newPost,
          mediaFiles: uploadedFiles
        })
      });

      setNewPost('');
      await fetchPosts();
    } catch (error) {
      console.error('Error creating post:', error);
      setError('Failed to create post. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleLike = async (postId) => {
    try {
      await apiRequest(`/posts/${postId}/like`, {
        method: 'POST'
      });
      await fetchPosts();
    } catch (error) {
      console.error('Error liking post:', error);
    }
  };

  const handleComment = async (postId, content) => {
    try {
      await apiRequest(`/posts/${postId}/comment`, {
        method: 'POST',
        body: JSON.stringify({ content })
      });
      await fetchPosts();
    } catch (error) {
      console.error('Error commenting:', error);
    }
  };

  const handleBrowsePublic = () => {
    console.log('🔄 handleBrowsePublic called - switching to public view');
    setCurrentView('public');
    fetchPublicPosts();
  };

  const handleLoginPrompt = () => {
    setCurrentView('landing');
  };

  const handlePostClick = (post) => {
    setSelectedPost(post);
    setCurrentView('post');
  };

  const handleBackToFeed = () => {
    setSelectedPost(null);
    setCurrentView('feed');
    navigate('/');
  };

  // Router handling
  useEffect(() => {
    if (currentPath.startsWith('/post/') && isLoggedIn) {
      const postId = currentPath.split('/')[2];
      const post = posts.find(p => p._id === postId);
      if (post) {
        setSelectedPost(post);
        setCurrentView('post');
      }
    }
  }, [currentPath, posts, isLoggedIn]);

  const handleFileUpload = async (files) => {
    console.log('File upload triggered:', files?.length);
  };

  // ✅ RENDER: Main app with enhanced error boundaries and loading states
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-slate-900 to-zinc-900">
      {currentView === 'landing' && (
        <LandingPage
          loginForm={loginForm}
          setLoginForm={setLoginForm}
          registerForm={registerForm}
          setRegisterForm={setRegisterForm}
          showRegister={showRegister}
          setShowRegister={setShowRegister}
          handleLogin={handleLogin}
          handleRegister={handleRegister}
          loading={loading}
          error={error}
          onBrowsePublic={handleBrowsePublic}
          termsAccepted={termsAccepted}
setTermsAccepted={setTermsAccepted}
showTermsModal={showTermsModal}
setShowTermsModal={setShowTermsModal}
        />
      )}

      {(currentView === 'feed' || currentView === 'profile' || currentView === 'chat' || currentView === 'post' || currentView === 'public') && (
        <>
          <Header
            currentView={currentView}
            setCurrentView={setCurrentView}
            apiStatus={apiStatus}
            handleLogout={handleLogout}
            user={user}
            selectedPost={selectedPost}
            onBackToFeed={handleBackToFeed}
            navigate={navigate}
            onSettingsClick={handleSettingsClick}
            fetchPublicPosts={fetchPublicPosts} 
          />

          <main className="container mx-auto px-4 py-6 max-w-2xl">
            {currentView === 'post' && selectedPost ? (
              <Post
                post={selectedPost}
                user={user}
                handleLike={handleLike}
                handleComment={handleComment}
                handleShare={() => {}}
                onPostClick={handlePostClick}
                isDetailView={true}
                navigate={navigate}
              />
            ) : currentView === 'public' ? (
              <div>
                <div className="text-center mb-6">
                  <h2 className="text-2xl font-bold text-white mb-2">Public Feed</h2>
                  <p className="text-slate-400">Browse posts from the SickoScoop community</p>
                  <button
                    onClick={() => setCurrentView('landing')}
                    className="mt-3 text-sm text-slate-500 hover:text-slate-400 underline"
                  >
                    ← Back to login
                  </button>
                </div>
                
                {publicPosts.length === 0 ? (
                  <div className="text-center py-12">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-white mx-auto mb-4"></div>
                    <p className="text-slate-400 mb-4">Loading public posts...</p>
                    <button
                      onClick={fetchPublicPosts}
                      className="text-sm text-blue-400 hover:text-blue-300 underline"
                    >
                      Retry loading posts
                    </button>
                  </div>
                ) : (
                  publicPosts.map(post => (
                    <Post
                      key={post._id}
                      post={post}
                      user={null}
                      handleLike={() => {}}
                      handleComment={() => {}}
                      handleShare={() => {}}
                      isPublicView={true}
                      onLoginPrompt={handleLoginPrompt}
                      onPostClick={handlePostClick}
                      navigate={navigate}
                    />
                  ))
                )}
              </div>
            ) : currentView === 'profile' ? (
              <div className="text-center py-12">
                <h2 className="text-2xl font-bold text-white mb-4">Profile</h2>
                <p className="text-slate-400">Profile features coming soon!</p>
              </div>
            ) : currentView === 'chat' ? (
              <div className="text-center py-12">
                <h2 className="text-2xl font-bold text-white mb-4">Chat</h2>
                <p className="text-slate-400">Chat features coming soon!</p>
              </div>
            ) : (
              <>
                {isLoggedIn && (
                  <PostCreator
                    user={user}
                    newPost={newPost}
                    setNewPost={setNewPost}
                    handlePost={handlePost}
                    loading={loading}
                    fileInputRef={fileInputRef}
                    handleFileUpload={handleFileUpload}
                  />
                )}

                {posts.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-slate-400 mb-4">No posts yet</p>
                    {isLoggedIn && (
                      <p className="text-slate-500 text-sm">Be the first to share something!</p>
                    )}
                  </div>
                ) : (
                  posts.map(post => (
                    <Post
                      key={post._id}
                      post={post}
                      user={user}
                      handleLike={handleLike}
                      handleComment={handleComment}
                      handleShare={() => {}}
                      onPostClick={handlePostClick}
                      navigate={navigate}
                    />
                  ))
                )}
              </>
            )}
          </main>
        </>
      )}
      {/* Settings Modal */}
      <SettingsModal 
        isOpen={showSettingsModal}
        onClose={() => setShowSettingsModal(false)}
        user={user}
      />
    </div>
  );
}