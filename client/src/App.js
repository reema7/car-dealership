import React, { useState, useEffect, createContext, useContext } from 'react';
import { ShoppingCart, User, Lock, Key, Car, CreditCard, Check, X, Menu, LogOut, Bot, AlertTriangle } from 'lucide-react';

// Add Tailwind CSS if not already included
if (!document.querySelector('#tailwind-css')) {
  const tailwindLink = document.createElement('link');
  tailwindLink.id = 'tailwind-css';
  tailwindLink.rel = 'stylesheet';
  tailwindLink.href = 'https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css';
  document.head.appendChild(tailwindLink);
}

// Auth Context
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// API Base URL (change to your server URL)
const API_BASE = 'https://car-dealership-xmlx-ps86to0co-reemas-projects-55d93993.vercel.app/';

// Utility functions for WebAuthn
const base64urlToBuffer = (base64url) => {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
};

const bufferToBase64url = (buffer) => {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

// API functions
const api = {
  async call(endpoint, options = {}) {
    const token = localStorage.getItem('token');
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
      },
      ...options,
    };

    if (config.body && typeof config.body === 'object') {
      config.body = JSON.stringify(config.body);
    }

    const response = await fetch(`${API_BASE}${endpoint}`, config);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'API request failed');
    }

    return data;
  },

  // Auth
  register: (userData) => api.call('/register', { method: 'POST', body: userData }),
  login: (credentials) => api.call('/login', { method: 'POST', body: credentials }),

  // Passkeys
  passkeyRegisterBegin: () => api.call('/passkey/register/begin', { method: 'POST' }),
  passkeyRegisterFinish: (credential) => api.call('/passkey/register/finish', { method: 'POST', body: { credential } }),
  passkeyAuthBegin: () => api.call('/passkey/authenticate/begin', { method: 'POST' }),
  passkeyAuthFinish: (credential) => api.call('/passkey/authenticate/finish', { method: 'POST', body: { credential } }),
  verifyHighValueAuth: (credential) => api.call('/passkey/verify-high-value', { method: 'POST', body: { credential } }),

  // Cars and Cart
  getCars: () => api.call('/cars'),
  getCar: (id) => api.call(`/cars/${id}`),
  addToCart: (carId) => api.call('/cart/add', { method: 'POST', body: { carId } }),
  getCart: () => api.call('/cart'),
  removeFromCart: (carId) => api.call(`/cart/${carId}`, { method: 'DELETE' }),
  createOrder: (orderData) => api.call('/orders', { method: 'POST', body: orderData }),
  getOrders: () => api.call('/orders'),
  getProfile: () => api.call('/profile'),
  
  // AI Detection
  reportAIDetection: (clientDetection) => api.call('/detect-ai', { method: 'POST', body: { clientDetection } }),
};

// AI/Bot Detection Hook
const useAIDetection = () => {
  const [isAI, setIsAI] = useState(false);
  const [detectionDetails, setDetectionDetails] = useState({});

  useEffect(() => {
    const detectAI = () => {
      const detection = {
        userAgent: navigator.userAgent,
        webdriver: navigator.webdriver,
        languages: navigator.languages,
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory,
        maxTouchPoints: navigator.maxTouchPoints,
        timestamp: Date.now()
      };

      // Check for automation indicators
      const indicators = {
        // User Agent checks
        isHeadless: /headless/i.test(detection.userAgent),
        isSelenium: /selenium/i.test(detection.userAgent),
        isPuppeteer: /puppeteer/i.test(detection.userAgent),
        isPlaywright: /playwright/i.test(detection.userAgent),
        isPhantom: /phantom/i.test(detection.userAgent),
        
        // WebDriver property
        hasWebDriver: detection.webdriver === true,
        
        // Browser automation detection
        hasAutomationExtensions: !!(window.navigator.webdriver || 
                                   window.__webdriver_evaluate || 
                                   window.__selenium_evaluate || 
                                   window.__webdriver_script_function ||
                                   window.__webdriver_script_func ||
                                   window.__webdriver_script_fn ||
                                   window.__fxdriver_evaluate ||
                                   window.__driver_unwrapped ||
                                   window.__webdriver_unwrapped ||
                                   window.__driver_evaluate ||
                                   window.__selenium_unwrapped ||
                                   window.__fxdriver_unwrapped),

        // Screen and hardware checks that might indicate VM
        suspiciousScreen: window.screen.width === 1024 && window.screen.height === 768, // Common VM resolution
        lowHardware: detection.hardwareConcurrency <= 2,
        noDeviceMemory: detection.deviceMemory === undefined,
        noTouch: detection.maxTouchPoints === 0 && /Mobile|Android|iPhone/i.test(detection.userAgent),

        // Language anomalies
        limitedLanguages: detection.languages.length <= 1,

        // Mouse movement patterns (basic check)
        noMouseActivity: true // Will be updated by mouse listener
      };

      // Check for common AI/automation IPs (you can expand this list)
      const checkIP = async () => {
        try {
          const response = await fetch('https://api.ipify.org?format=json');
          const data = await response.json();
          const ip = data.ip;
          
          // Known cloud/automation service IP ranges (simplified)
          const automationIPRanges = [
            /^34\./, // Google Cloud
            /^35\./, // Google Cloud
            /^52\./, // AWS
            /^54\./, // AWS
            /^18\./, // AWS
            /^3\./, // AWS
            /^13\./, // Azure
            /^40\./, // Azure
            /^104\./, // Azure
            /^178\.128\./, // DigitalOcean
            /^167\.99\./, // DigitalOcean
          ];
          
          indicators.suspiciousIP = automationIPRanges.some(range => range.test(ip));
          detection.ipAddress = ip;
          
          // Update detection
          updateDetection();
        } catch (error) {
          console.log('Could not fetch IP for AI detection');
        }
      };

      const updateDetection = () => {
        const positiveIndicators = Object.values(indicators).filter(Boolean).length;
        const isLikelyAI = positiveIndicators >= 2; // Threshold for AI detection
        
        setIsAI(isLikelyAI);
        setDetectionDetails({ ...detection, indicators, score: positiveIndicators });
        
        // Add debugging info
        console.log('🔍 AI Detection Status:', {
          isLikelyAI: positiveIndicators >= 2,
          score: positiveIndicators,
          indicators: Object.entries(indicators).filter(([k, v]) => v === true),
          userAgent: detection.userAgent
        });
        
        // Log detection for debugging
        if (isLikelyAI) {
          console.log('🤖 AI/Automation detected:', { 
            score: positiveIndicators, 
            indicators: Object.entries(indicators).filter(([k, v]) => v)
          });
        }
      };

      // Set up mouse movement detection
      let mouseEvents = 0;
      const mouseHandler = () => {
        mouseEvents++;
        if (mouseEvents > 5) {
          indicators.noMouseActivity = false;
          updateDetection();
          document.removeEventListener('mousemove', mouseHandler);
        }
      };
      
      document.addEventListener('mousemove', mouseHandler);
      
      // Clean up mouse listener after 10 seconds
      setTimeout(() => {
        document.removeEventListener('mousemove', mouseHandler);
      }, 10000);

      // Check IP
      checkIP();
      
      // Initial detection update
      updateDetection();
      
      // Report to server for combined analysis
      setTimeout(() => {
        api.reportAIDetection(detection).catch(err => 
          console.log('Could not report AI detection to server:', err.message)
        );
      }, 2000);
    };

    detectAI();
  }, []);

  return { isAI, detectionDetails };
};

// AI Detection Banner Component
const AIDetectionBanner = ({ isAI, detectionDetails }) => {
  const [dismissed, setDismissed] = useState(false);
  
  if (!isAI || dismissed) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      backgroundColor: '#f59e0b',
      color: 'white',
      padding: '12px 16px',
      zIndex: 1000,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <Bot size={24} />
        <div>
          <strong>AI/Automation Detected</strong>
          <div style={{ fontSize: '14px', opacity: 0.9 }}>
            This website is being accessed by an automated agent or AI operator
          </div>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ fontSize: '12px', opacity: 0.8 }}>
          Detection Score: {detectionDetails.score || 0}/10
        </div>
        <button
          onClick={() => setDismissed(true)}
          style={{
            background: 'rgba(255,255,255,0.2)',
            border: 'none',
            color: 'white',
            padding: '4px',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          <X size={16} />
        </button>
      </div>
    </div>
  );
};

// Auth Provider Component
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    
    if (token && userData) {
      setUser(JSON.parse(userData));
    }
    setLoading(false);
  }, []);

  const login = async (credentials) => {
    const response = await api.login(credentials);
    localStorage.setItem('token', response.token);
    localStorage.setItem('user', JSON.stringify(response.user));
    setUser(response.user);
    return response;
  };

  const register = async (userData) => {
    const response = await api.register(userData);
    localStorage.setItem('token', response.token);
    localStorage.setItem('user', JSON.stringify(response.user));
    setUser(response.user);
    return response;
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
  };

  const loginWithPasskey = async () => {
    try {
      // Get authentication options
      const options = await api.passkeyAuthBegin();
      
      // Convert challenge to buffer
      const publicKeyCredentialRequestOptions = {
        ...options,
        challenge: base64urlToBuffer(options.challenge),
        allowCredentials: options.allowCredentials?.map(cred => ({
          ...cred,
          id: base64urlToBuffer(cred.id)
        }))
      };

      // Get credential from authenticator
      const credential = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
      });

      // Format credential for server
      const credentialForServer = {
        id: credential.id,
        type: credential.type,
        response: {
          authenticatorData: bufferToBase64url(credential.response.authenticatorData),
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          signature: bufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
        }
      };

      // Verify with server
      const response = await api.passkeyAuthFinish(credentialForServer);
      
      localStorage.setItem('token', response.token);
      localStorage.setItem('user', JSON.stringify(response.user));
      setUser(response.user);
      
      return response;
    } catch (error) {
      console.error('Passkey authentication failed:', error);
      throw new Error('Passkey authentication failed');
    }
  };

  const value = {
    user,
    login,
    register,
    logout,
    loginWithPasskey,
    isAuthenticated: !!user,
    loading
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Login Component
const LoginForm = ({ onClose, onSwitchToRegister }) => {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, loginWithPasskey } = useAuth();

  const handleSubmit = async () => {
    setLoading(true);
    setError('');

    try {
      await login(formData);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handlePasskeyLogin = async () => {
    setLoading(true);
    setError('');

    try {
      await loginWithPasskey();
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-lg max-w-md w-full">
      <h2 className="text-2xl font-bold mb-4">Login</h2>
      
      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          {error}
        </div>
      )}

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
          <input
            type="email"
            required
            value={formData.email}
            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
          <input
            type="password"
            required
            value={formData.password}
            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <button
          onClick={handleSubmit}
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center justify-center gap-2"
        >
          <Lock size={16} />
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </div>

      <div className="mt-4 text-center">
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300" />
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white text-gray-500">or</span>
          </div>
        </div>

        <button
          onClick={handlePasskeyLogin}
          disabled={loading}
          className="mt-4 w-full bg-green-600 text-white py-2 rounded-md hover:bg-green-700 disabled:opacity-50 flex items-center justify-center gap-2"
        >
          <Key size={16} />
          Login with Passkey
        </button>
      </div>

      <p className="mt-4 text-center text-sm text-gray-600">
        Don't have an account?{' '}
        <button
          onClick={onSwitchToRegister}
          className="text-blue-600 hover:underline"
        >
          Register here
        </button>
      </p>
    </div>
  );
};

// Register Component
const RegisterForm = ({ onClose, onSwitchToLogin }) => {
  const [formData, setFormData] = useState({ name: '', email: '', password: '', confirmPassword: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { register } = useAuth();

  const handleSubmit = async () => {
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);

    try {
      await register({
        name: formData.name,
        email: formData.email,
        password: formData.password
      });
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-lg max-w-md w-full">
      <h2 className="text-2xl font-bold mb-4">Register</h2>
      
      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          {error}
        </div>
      )}

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
          <input
            type="text"
            required
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
          <input
            type="email"
            required
            value={formData.email}
            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
          <input
            type="password"
            required
            value={formData.password}
            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
          <input
            type="password"
            required
            value={formData.confirmPassword}
            onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <button
          onClick={handleSubmit}
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? 'Creating Account...' : 'Create Account'}
        </button>
      </div>

      <p className="mt-4 text-center text-sm text-gray-600">
        Already have an account?{' '}
        <button
          onClick={onSwitchToLogin}
          className="text-blue-600 hover:underline"
        >
          Login here
        </button>
      </p>
    </div>
  );
};

// Passkey Setup Component
const PasskeySetup = () => {
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');
  const [userProfile, setUserProfile] = useState(null);
  const [profileLoading, setProfileLoading] = useState(true);

  // Check if user already has passkeys
  useEffect(() => {
    const checkUserPasskeys = async () => {
      try {
        const profile = await api.getProfile();
        setUserProfile(profile);
      } catch (error) {
        console.error('Could not load user profile:', error);
      } finally {
        setProfileLoading(false);
      }
    };

    checkUserPasskeys();
  }, [success]); // Reload when passkey is successfully created

  const setupPasskey = async () => {
    setLoading(true);
    setError('');
    setSuccess(false);

    try {
      // Get registration options from server
      const options = await api.passkeyRegisterBegin();
      
      // Convert challenge and user ID to buffers
      const publicKeyCredentialCreationOptions = {
        ...options,
        challenge: base64urlToBuffer(options.challenge),
        user: {
          ...options.user,
          id: base64urlToBuffer(options.user.id)
        }
      };

      // Create credential
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      });

      // Format credential for server
      const credentialForServer = {
        id: credential.id,
        type: credential.type,
        response: {
          attestationObject: bufferToBase64url(credential.response.attestationObject),
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          publicKey: bufferToBase64url(credential.response.publicKey || new ArrayBuffer(0))
        }
      };

      // Send to server
      await api.passkeyRegisterFinish(credentialForServer);
      setSuccess(true);
    } catch (err) {
      console.error('Passkey setup failed:', err);
      setError('Failed to setup passkey. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (profileLoading) {
    return (
      <div className="bg-white p-6 rounded-lg shadow-lg">
        <div className="text-center text-gray-500">Loading passkey status...</div>
      </div>
    );
  }

  // Don't show the setup component if user already has passkeys
  const hasPasskeys = userProfile?.passkeys && userProfile.passkeys.length > 0;

  if (hasPasskeys) {
    return (
      <div className="bg-green-50 p-6 rounded-lg shadow-lg border border-green-200">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-green-800">
          <Check size={20} />
          Passkey Active
        </h3>
        
        <p className="text-green-700 mb-4">
          Your account is secured with {userProfile.passkeys.length} passkey{userProfile.passkeys.length > 1 ? 's' : ''}. 
          You can use biometric authentication for secure login.
        </p>

        <div className="space-y-2">
          {userProfile.passkeys.map((passkey, index) => (
            <div key={passkey.id} className="text-sm text-green-600 bg-green-100 p-2 rounded">
              <strong>Passkey {index + 1}:</strong> Created {new Date(passkey.createdAt).toLocaleDateString()}
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white p-6 rounded-lg shadow-lg">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Key size={20} />
        Setup Passkey
      </h3>
      
      <p className="text-gray-600 mb-4">
        Secure your account with a passkey for quick and safe login without passwords.
      </p>

      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4 flex items-center gap-2">
          <Check size={16} />
          Passkey setup successful! The component will refresh automatically.
        </div>
      )}

      <button
        onClick={setupPasskey}
        disabled={loading || success}
        className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700 disabled:opacity-50 flex items-center gap-2"
      >
        <Key size={16} />
        {loading ? 'Setting up...' : success ? 'Passkey Active' : 'Setup Passkey'}
      </button>
    </div>
  );
};

// Car Card Component
const CarCard = ({ car, onAddToCart, inCart }) => {
  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden hover:shadow-lg transition-shadow" style={{ minHeight: '500px', display: 'flex', flexDirection: 'column' }}>
      <img
        src={car.image}
        alt={`${car.make} ${car.model}`}
        className="w-full object-cover"
        style={{ height: '200px', objectFit: 'cover' }}
      />
      <div className="p-4" style={{ flex: '1', display: 'flex', flexDirection: 'column' }}>
        <h3 className="text-xl font-semibold mb-2">{car.make} {car.model}</h3>
        <div className="text-gray-600 space-y-1 mb-2">
          <p>Year: {car.year}</p>
          <p>Mileage: {car.mileage.toLocaleString()} miles</p>
          <p>Color: {car.color}</p>
        </div>
        <p className="text-sm text-gray-500 mb-4" style={{ flex: '1' }}>{car.description}</p>
        <div className="flex items-center justify-between mt-auto">
          <span className="text-2xl font-bold text-green-600">
            ${car.price.toLocaleString()}
          </span>
          <button
            onClick={() => onAddToCart(car.id)}
            disabled={inCart}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
          >
            <ShoppingCart size={16} />
            {inCart ? 'In Cart' : 'Add to Cart'}
          </button>
        </div>
      </div>
    </div>
  );
};

// Cart Component
const Cart = ({ onClose }) => {
  const [cartItems, setCartItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadCart();
  }, []);

  const loadCart = async () => {
    try {
      const items = await api.getCart();
      setCartItems(items);
    } catch (error) {
      console.error('Failed to load cart:', error);
    } finally {
      setLoading(false);
    }
  };

  const removeFromCart = async (carId) => {
    try {
      await api.removeFromCart(carId);
      setCartItems(cartItems.filter(car => car.id !== carId));
    } catch (error) {
      console.error('Failed to remove from cart:', error);
    }
  };

  const total = cartItems.reduce((sum, car) => sum + car.price, 0);

  if (loading) {
    return <div className="text-center py-8">Loading cart...</div>;
  }

  return (
    <div className="bg-white p-6 rounded-lg shadow-lg max-w-2xl w-full max-h-[80vh] overflow-y-auto">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold">Shopping Cart</h2>
        <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
          <X size={24} />
        </button>
      </div>

      {cartItems.length === 0 ? (
        <p className="text-gray-500 text-center py-8">Your cart is empty</p>
      ) : (
        <>
          <div className="space-y-4 mb-6">
            {cartItems.map(car => (
              <div key={car.id} className="flex items-center gap-4 p-4 border rounded-lg">
                <img
                  src={car.image}
                  alt={`${car.make} ${car.model}`}
                  className="w-20 h-20 object-cover rounded"
                />
                <div className="flex-1">
                  <h3 className="font-semibold">{car.make} {car.model}</h3>
                  <p className="text-gray-600">{car.year} • {car.color}</p>
                  <p className="text-lg font-bold text-green-600">
                    ${car.price.toLocaleString()}
                  </p>
                </div>
                <button
                  onClick={() => removeFromCart(car.id)}
                  className="text-red-500 hover:text-red-700"
                >
                  <X size={20} />
                </button>
              </div>
            ))}
          </div>

          <div className="border-t pt-4">
            <div className="flex justify-between items-center mb-4">
              <span className="text-xl font-semibold">Total:</span>
              <span className="text-2xl font-bold text-green-600">
                ${total.toLocaleString()}
              </span>
            </div>
            <CheckoutForm cartItems={cartItems} total={total} onSuccess={onClose} />
          </div>
        </>
      )}
    </div>
  );
};

// Checkout Form Component
const CheckoutForm = ({ cartItems, total, onSuccess }) => {
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    phone: '',
    address: '',
    city: '',
    state: '',
    zipCode: '',
    cardNumber: '',
    expiryDate: '',
    cvv: '',
    cardholderName: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { isAuthenticated } = useAuth();
  const { isAI } = useAIDetection();

  // Only require passkey auth if AI is detected AND purchase is over $50k AND user is authenticated
  const requiresPasskeyAuth = isAI && total > 50000 && isAuthenticated;

  const performHighValuePasskeyAuth = async () => {
    try {
      // Get authentication options for high-value transaction
      const options = await api.passkeyAuthBegin();
      
      // Add txAuthSimple extension for high-value purchases
      const publicKeyCredentialRequestOptions = {
        ...options,
        challenge: base64urlToBuffer(options.challenge),
        allowCredentials: options.allowCredentials?.map(cred => ({
          ...cred,
          id: base64urlToBuffer(cred.id)
        })),
        extensions: {
          txAuthSimple: `AI Agent is about to make a purchase of over $${total.toLocaleString()}. Do you want to allow this?`
        }
      };

      // Get credential from authenticator with transaction auth
      const credential = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
      });

      // Format credential for server
      const credentialForServer = {
        id: credential.id,
        type: credential.type,
        response: {
          authenticatorData: bufferToBase64url(credential.response.authenticatorData),
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          signature: bufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
        },
        // Include extension results
        extensions: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {}
      };

      // Verify high-value transaction authentication
      await api.verifyHighValueAuth(credentialForServer);
      
      return true;
    } catch (error) {
      console.error('High-value passkey authentication failed:', error);
      throw new Error('AI transaction authentication failed. Purchase cancelled for security.');
    }
  };

  const handleSubmit = async () => {
    setLoading(true);
    setError('');

    try {
      // Only perform passkey auth if it's actually required (AI + high value)
      if (requiresPasskeyAuth) {
        try {
          await performHighValuePasskeyAuth();
        } catch (authError) {
          setError(authError.message);
          setLoading(false);
          return;
        }
      }

      const orderData = {
        carIds: cartItems.map(car => car.id),
        customerInfo: {
          firstName: formData.firstName,
          lastName: formData.lastName,
          email: formData.email,
          phone: formData.phone,
          address: formData.address,
          city: formData.city,
          state: formData.state,
          zipCode: formData.zipCode
        },
        paymentInfo: {
          cardNumber: formData.cardNumber,
          expiryDate: formData.expiryDate,
          cvv: formData.cvv,
          cardholderName: formData.cardholderName
        },
        requiresHighValueAuth: requiresPasskeyAuth,
        isAITransaction: isAI
      };

      const response = await api.createOrder(orderData);
      alert(`Order created successfully! Order ID: ${response.orderId}`);
      onSuccess();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  console.log('Checkout Debug:', { 
    isAI, 
    total, 
    isAuthenticated, 
    requiresPasskeyAuth,
    totalOver50k: total > 50000 
  });

  return (
    <div className="space-y-4">
      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {/* Only show AI warning if AI is detected AND high value */}
      {requiresPasskeyAuth && (
        <div className="bg-red-100 border border-red-400 text-red-800 px-4 py-3 rounded mb-4">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Bot size={16} />
            <strong>AI High-Value Transaction Security</strong>
          </div>
          <p className="text-sm mt-1">
            AI detected making a purchase over $50,000. Additional passkey authentication required for security.
          </p>
        </div>
      )}

      {/* Show human high-value message only if NOT AI but high value */}
      {total > 50000 && !isAI && (
        <div className="bg-blue-100 border border-blue-400 text-blue-800 px-4 py-3 rounded mb-4">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CreditCard size={16} />
            <strong>High-Value Transaction</strong>
          </div>
          <p className="text-sm mt-1">
            Large purchase detected ($50,000+). No additional authentication required for human users.
          </p>
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">First Name</label>
          <input
            type="text"
            required
            value={formData.firstName}
            onChange={(e) => setFormData({ ...formData, firstName: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Last Name</label>
          <input
            type="text"
            required
            value={formData.lastName}
            onChange={(e) => setFormData({ ...formData, lastName: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
        <input
          type="email"
          required
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Card Number</label>
        <input
          type="text"
          required
          placeholder="1234 5678 9012 3456"
          value={formData.cardNumber}
          onChange={(e) => setFormData({ ...formData, cardNumber: e.target.value })}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Expiry Date</label>
          <input
            type="text"
            required
            placeholder="MM/YY"
            value={formData.expiryDate}
            onChange={(e) => setFormData({ ...formData, expiryDate: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">CVV</label>
          <input
            type="text"
            required
            placeholder="123"
            value={formData.cvv}
            onChange={(e) => setFormData({ ...formData, cvv: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      <button
        onClick={handleSubmit}
        disabled={loading}
        style={{
          width: '100%',
          backgroundColor: requiresPasskeyAuth ? '#dc2626' : (total > 50000 ? '#d97706' : '#16a34a'),
          color: 'white',
          padding: '12px',
          borderRadius: '6px',
          border: 'none',
          cursor: loading ? 'not-allowed' : 'pointer',
          opacity: loading ? 0.5 : 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '8px',
          fontSize: '16px',
          fontWeight: '500'
        }}
      >
        {requiresPasskeyAuth ? <Bot size={16} /> : (total > 50000 ? <Key size={16} /> : <CreditCard size={16} />)}
        {loading 
          ? (requiresPasskeyAuth ? 'AI Auth Required...' : 'Processing...') 
          : (requiresPasskeyAuth 
              ? `AI Security Check - $${total.toLocaleString()}` 
              : (total > 50000 && !isAI
                  ? `High-Value Purchase - $${total.toLocaleString()} (No Auth Required)`
                  : `Complete Purchase - $${total.toLocaleString()}`
                )
            )
        }
      </button>
    </div>
  );
};

// Main App Component
const CarDealershipApp = () => {
  const [cars, setCars] = useState([]);
  const [cartItems, setCartItems] = useState([]);
  const [showLogin, setShowLogin] = useState(false);
  const [showRegister, setShowRegister] = useState(false);
  const [showCart, setShowCart] = useState(false);
  const [loading, setLoading] = useState(true);
  const { user, logout, isAuthenticated } = useAuth();
  const { isAI, detectionDetails } = useAIDetection();

  useEffect(() => {
    loadCars();
    if (isAuthenticated) {
      loadCart();
    }
  }, [isAuthenticated]);

  const loadCars = async () => {
    try {
      const carList = await api.getCars();
      setCars(carList);
    } catch (error) {
      console.error('Failed to load cars:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadCart = async () => {
    if (!isAuthenticated) return;
    try {
      const items = await api.getCart();
      setCartItems(items);
    } catch (error) {
      console.error('Failed to load cart:', error);
    }
  };

  const addToCart = async (carId) => {
    if (!isAuthenticated) {
      setShowLogin(true);
      return;
    }

    try {
      await api.addToCart(carId);
      loadCart();
    } catch (error) {
      console.error('Failed to add to cart:', error);
    }
  };

  const isInCart = (carId) => {
    return cartItems.some(item => item.id === carId);
  };

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#f3f4f6' }}>
      {/* AI Detection Banner */}
      <AIDetectionBanner isAI={isAI} detectionDetails={detectionDetails} />
      
      {/* Header */}
      <header className="bg-white shadow-md" style={{ marginTop: isAI ? '60px' : '0' }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '0 16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', height: '64px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Car className="text-blue-600" size={32} />
              <h1 style={{ fontSize: '24px', fontWeight: 'bold', color: '#111827', margin: 0 }}>AutoDealer Pro</h1>
              {isAI && (
                <div style={{ 
                  backgroundColor: '#f59e0b', 
                  color: 'white', 
                  padding: '4px 8px', 
                  borderRadius: '12px', 
                  fontSize: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}>
                  <Bot size={14} />
                  AI Mode
                </div>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              {isAuthenticated ? (
                <>
                  <button
                    onClick={() => setShowCart(true)}
                    style={{ position: 'relative', padding: '8px', color: '#6b7280', background: 'none', border: 'none', cursor: 'pointer' }}
                  >
                    <ShoppingCart size={24} />
                    {cartItems.length > 0 && (
                      <span style={{
                        position: 'absolute',
                        top: '-4px',
                        right: '-4px',
                        background: '#ef4444',
                        color: 'white',
                        fontSize: '12px',
                        borderRadius: '50%',
                        height: '20px',
                        width: '20px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                      }}>
                        {cartItems.length}
                      </span>
                    )}
                  </button>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <User size={20} />
                    <span style={{ fontSize: '14px', fontWeight: '500' }}>{user.name}</span>
                  </div>
                  <button
                    onClick={logout}
                    style={{ color: '#6b7280', background: 'none', border: 'none', cursor: 'pointer' }}
                  >
                    <LogOut size={20} />
                  </button>
                </>
              ) : (
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => setShowLogin(true)}
                    style={{
                      background: '#2563eb',
                      color: 'white',
                      padding: '8px 16px',
                      borderRadius: '6px',
                      border: 'none',
                      cursor: 'pointer'
                    }}
                  >
                    Login
                  </button>
                  <button
                    onClick={() => setShowRegister(true)}
                    style={{
                      border: '1px solid #2563eb',
                      color: '#2563eb',
                      padding: '8px 16px',
                      borderRadius: '6px',
                      background: 'white',
                      cursor: 'pointer'
                    }}
                  >
                    Register
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main style={{ maxWidth: '1200px', margin: '0 auto', padding: '32px 16px' }}>
        {/* Hero Section */}
        <div style={{ textAlign: 'center', marginBottom: '48px' }}>
          <h2 style={{ fontSize: '36px', fontWeight: 'bold', color: '#111827', marginBottom: '16px' }}>
            Find Your Perfect Car
          </h2>
          <p style={{ fontSize: '20px', color: '#6b7280' }}>
            Browse our extensive collection of quality vehicles
          </p>
        </div>

        {/* Passkey Setup for Authenticated Users */}
        {isAuthenticated && (
          <div style={{ marginBottom: '32px' }}>
            <PasskeySetup />
          </div>
        )}

        {/* Car Listings */}
        {loading ? (
          <div className="text-center py-12">
            <div className="text-lg">Loading cars...</div>
          </div>
        ) : (
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', 
            gap: '24px',
            padding: '0 16px'
          }}>
            {cars.map(car => (
              <CarCard
                key={car.id}
                car={car}
                onAddToCart={addToCart}
                inCart={isInCart(car.id)}
              />
            ))}
          </div>
        )}
      </main>

      {/* Modals */}
      {showLogin && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <LoginForm
            onClose={() => setShowLogin(false)}
            onSwitchToRegister={() => {
              setShowLogin(false);
              setShowRegister(true);
            }}
          />
        </div>
      )}

      {showRegister && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <RegisterForm
            onClose={() => setShowRegister(false)}
            onSwitchToLogin={() => {
              setShowRegister(false);
              setShowLogin(true);
            }}
          />
        </div>
      )}

      {showCart && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <Cart onClose={() => setShowCart(false)} />
        </div>
      )}
    </div>
  );
};

// Root App with Auth Provider
const App = () => {
  return (
    <AuthProvider>
      <CarDealershipApp />
    </AuthProvider>
  );
};

export default App;
