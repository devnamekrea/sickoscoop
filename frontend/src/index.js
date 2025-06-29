// src/index.js - Fixed React 18 entry point
import React from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App';

// ✅ FIX FOR REACT ERROR #299: Ensure root element exists
const rootElement = document.getElementById('root');

if (!rootElement) {
  console.error('❌ CRITICAL: Root element not found! Make sure you have <div id="root"></div> in your HTML');
  throw new Error('Root element not found');
}

// ✅ PROPER REACT 18 INITIALIZATION
const root = createRoot(rootElement);

// ✅ RENDER WITH ERROR BOUNDARY
try {
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
  console.log('✅ SickoScoop React app rendered successfully');
} catch (error) {
  console.error('❌ React rendering error:', error);
  
  // Fallback rendering without StrictMode
  root.render(<App />);
}