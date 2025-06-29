import { useState, useEffect } from 'react';
import { apiCall } from '../config/api';

export const useAuth = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  // Check for existing auth on app load
  useEffect(() => {
    const token = localStorage.getItem('authToken');
    const userData = localStorage.getItem('userData');
    
    if (token && userData) {
      try {
        const parsedUser = JSON.parse(userData);
        setUser(parsedUser);
        setIsLoggedIn(true);
      } catch (err) {
        console.error('Error parsing stored user data:', err);
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
      }
    }
  }, []);

  const login = async (credentials) => {
    setLoading(true);
    setError(null);
    
    try {
      console.log('🔐 Attempting login with:', credentials.email);
      
      const response = await apiCall('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email: credentials.email,
          password: credentials.password
        })
      });

      console.log('✅ Login response:', response);

      if (response.token && response.user) {
        // Store auth data
        localStorage.setItem('authToken', response.token);
        localStorage.setItem('userData', JSON.stringify(response.user));
        
        // Update state
        setUser(response.user);
        setIsLoggedIn(true);
        
        return { success: true, user: response.user };
      } else {
        throw new Error('Invalid response format');
      }
      
    } catch (err) {
      console.error('❌ Login error:', err);
      setError(err.message);
      return { 
        success: false, 
        error: err.message || 'Login failed. Please check your credentials.' 
      };
    } finally {
      setLoading(false);
    }
  };

  const register = async (userData) => {
    setLoading(true);
    setError(null);
    
    try {
      console.log('📝 Attempting registration with:', userData.email);
      
      const response = await apiCall('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          name: userData.name,
          email: userData.email,
          password: userData.password
        })
      });

      console.log('✅ Registration response:', response);

      if (response.token && response.user) {
        // Store auth data
        localStorage.setItem('authToken', response.token);
        localStorage.setItem('userData', JSON.stringify(response.user));
        
        // Update state
        setUser(response.user);
        setIsLoggedIn(true);
        
        return { success: true, user: response.user };
      } else {
        throw new Error('Invalid response format');
      }
      
    } catch (err) {
      console.error('❌ Registration error:', err);
      setError(err.message);
      return { 
        success: false, 
        error: err.message || 'Registration failed. Please try again.' 
      };
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    console.log('🚪 Logging out user');
    
    // Clear storage
    localStorage.removeItem('authToken');
    localStorage.removeItem('userData');
    
    // Clear state
    setUser(null);
    setIsLoggedIn(false);
    setError(null);
  };

  const clearError = () => {
    setError(null);
  };

  // Get current auth token
  const getToken = () => {
    return localStorage.getItem('authToken');
  };

  return {
    user,
    loading,
    error,
    isLoggedIn,
    login,
    register,
    logout,
    clearError,
    getToken
  };
};