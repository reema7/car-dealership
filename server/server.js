// server.js - Node.js/Express Server with Passkey Authentication
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Dynamic domain configuration
const isDevelopment = process.env.NODE_ENV !== 'production';
const DOMAIN = isDevelopment ? 'localhost' : 'car-dealership-client.vercel.app';
const CLIENT_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:3001', 
  'https://car-dealership-client.vercel.app',
  'https://car-dealership-xmlx.vercel.app'
];

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    // Allow all origins in development
    if (isDevelopment) return callback(null, true);
    
    // Check against allowed origins in production
    if (CLIENT_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    
    // Log and allow for debugging
    console.log('CORS blocked origin:', origin);
    return callback(null, true); // Allow for now, can be restricted later
  },
  credentials: true
}));
app.use(express.json());
app.use(express.static('public'));

// AI/Bot detection middleware
const detectAI = (req, res, next) => {
  const userAgent = req.get('User-Agent') || '';
  const xForwardedFor = req.get('X-Forwarded-For');
  const xRealIP = req.get('X-Real-IP');
  const clientIP = xForwardedFor || xRealIP || req.connection.remoteAddress || req.ip;
  
  // Detection indicators
  const indicators = {
    // User Agent analysis
    isHeadless: /headless/i.test(userAgent),
    isSelenium: /selenium/i.test(userAgent),
    isPuppeteer: /puppeteer/i.test(userAgent),
    isPlaywright: /playwright/i.test(userAgent),
    isPhantom: /phantom/i.test(userAgent),
    isBot: /bot|crawler|spider|scraper/i.test(userAgent),
    
    // Missing typical browser headers
    noAcceptLanguage: !req.get('Accept-Language'),
    noAcceptEncoding: !req.get('Accept-Encoding'),
    
    // Automation-specific headers
    hasWebDriverHeader: !!(req.get('webdriver') || req.get('x-webdriver')),
    
    // IP-based detection (cloud providers commonly used for automation)
    isCloudIP: /^(34\.|35\.|52\.|54\.|18\.|3\.|13\.|40\.|104\.|178\.128\.|167\.99\.)/.test(clientIP),
    
    // Request timing patterns (too fast/regular)
    timestamp: Date.now()
  };
  
  // Calculate AI probability score
  const positiveIndicators = Object.values(indicators).filter(v => v === true).length;
  const isLikelyAI = positiveIndicators >= 2;
  
  // Log AI detection
  if (isLikelyAI) {
    console.log('🤖 AI/Bot detected:', {
      ip: clientIP,
      userAgent: userAgent,
      score: positiveIndicators,
      indicators: Object.entries(indicators).filter(([k, v]) => v === true).map(([k]) => k),
      endpoint: req.path,
      method: req.method,
      timestamp: new Date().toISOString()
    });
  }
  
  // Add detection info to request
  req.aiDetection = {
    isLikelyAI,
    score: positiveIndicators,
    indicators,
    clientIP,
    userAgent
  };
  
  next();
};

app.use(detectAI);

// In-memory storage (use a real database in production)
const users = new Map(); // Key: user.id (not email!)
const usersByEmail = new Map(); // Key: email, Value: user.id
const cars = new Map();
const orders = new Map();
const passkeys = new Map(); // Store passkey credentials
const authChallenges = new Map(); // Store temporary challenges by session ID

// Initialize sample car data
const initializeCars = () => {
  const sampleCars = [
    {
      id: '1',
      make: 'Tesla',
      model: 'Model 3',
      year: 2023,
      price: 45000,
      mileage: 5000,
      color: 'White',
      image: 'https://images.unsplash.com/photo-1560958089-b8a1929cea89?w=400',
      description: 'Electric sedan with autopilot features'
    },
    {
      id: '2',
      make: 'BMW',
      model: 'X5',
      year: 2022,
      price: 65000,
      mileage: 12000,
      color: 'Black',
      image: 'https://images.unsplash.com/photo-1555215695-3004980ad54e?w=400',
      description: 'Luxury SUV with premium interior'
    },
    {
      id: '3',
      make: 'Honda',
      model: 'Civic',
      year: 2023,
      price: 28000,
      mileage: 8000,
      color: 'Blue',
      image: 'https://images.unsplash.com/photo-1549317661-bd32c8ce0db2?w=400',
      description: 'Reliable compact car with excellent fuel economy'
    }
  ];
  
  sampleCars.forEach(car => cars.set(car.id, car));
};

initializeCars();

// Helper functions for WebAuthn
const generateChallenge = () => {
  return crypto.randomBytes(32).toString('base64url');
};

const verifySignature = (signature, authenticatorData, clientDataJSON, publicKey) => {
  // Simplified signature verification (use a proper WebAuthn library in production)
  try {
    const clientDataHash = crypto.createHash('sha256').update(Buffer.from(clientDataJSON, 'base64url')).digest();
    const signedData = Buffer.concat([Buffer.from(authenticatorData, 'base64url'), clientDataHash]);
    
    // This is a simplified verification - use @simplewebauthn/server in production
    return true; // Placeholder for actual verification
  } catch (error) {
    return false;
  }
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log('JWT verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // Verify user still exists
    const user = users.get(decoded.id);
    if (!user) {
      console.log('User not found for token:', decoded.id);
      return res.status(404).json({ error: 'User not found' });
    }
    
    req.user = decoded;
    next();
  });
};

// Routes

// User registration
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    console.log('Registration attempt for email:', email);

    if (usersByEmail.has(email)) {
      console.log('User already exists for email:', email);
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    const user = {
      id: userId,
      email,
      password: hashedPassword,
      name,
      cart: [],
      passkeys: [],
      createdAt: new Date().toISOString()
    };

    // Store user by both ID and email mapping
    users.set(userId, user);
    usersByEmail.set(email, userId);

    console.log('User registered successfully:', { id: userId, email, name });
    console.log('Total users now:', users.size);
    console.log('Email mappings:', Array.from(usersByEmail.entries()));

    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: userId, email, name }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('Login attempt for email:', email);

    const userId = usersByEmail.get(email);
    console.log('Found userId for email:', userId);
    
    if (!userId) {
      console.log('No userId found for email:', email);
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = users.get(userId);
    console.log('Found user for userId:', userId, user ? 'exists' : 'not found');
    
    if (!user) {
      console.log('User object not found for userId:', userId);
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    console.log('Password validation result:', validPassword);
    
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: '24h' });

    console.log('User logged in successfully:', { id: user.id, email });

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, email, name: user.name }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Passkey registration - Generate options
app.post('/api/passkey/register/begin', authenticateToken, (req, res) => {
  try {
    const user = users.get(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const challenge = generateChallenge();
    const sessionId = uuidv4();
    const userId = Buffer.from(user.id).toString('base64url');

    const options = {
      rp: {
        name: "AutoDealer Pro",
        id: DOMAIN
      },
      user: {
        id: userId,
        name: user.email,
        displayName: user.name
      },
      challenge: challenge,
      pubKeyCredParams: [
        { alg: -7, type: "public-key" }, // ES256
        { alg: -257, type: "public-key" } // RS256
      ],
      timeout: 60000,
      attestation: "direct",
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        residentKey: "preferred"
      }
    };

    // Store challenge with session ID
    authChallenges.set(sessionId, {
      challenge,
      userId: user.id,
      type: 'registration',
      created: Date.now()
    });

    // Clean up old challenges (older than 5 minutes)
    const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
    for (const [key, value] of authChallenges.entries()) {
      if (value.created < fiveMinutesAgo) {
        authChallenges.delete(key);
      }
    }

    res.json({ ...options, sessionId });
  } catch (error) {
    console.error('Passkey registration begin error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Passkey registration - Verify credential
app.post('/api/passkey/register/finish', authenticateToken, (req, res) => {
  try {
    const { credential, sessionId } = req.body;
    
    if (!sessionId || !authChallenges.has(sessionId)) {
      return res.status(400).json({ error: 'Invalid registration session' });
    }

    const challengeData = authChallenges.get(sessionId);
    if (challengeData.userId !== req.user.id || challengeData.type !== 'registration') {
      return res.status(400).json({ error: 'Invalid registration session' });
    }

    const user = users.get(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Store the passkey credential
    const passkeyId = uuidv4();
    const passkey = {
      id: passkeyId,
      credentialId: credential.id,
      publicKey: credential.response.publicKey,
      userId: user.id,
      counter: 0,
      createdAt: new Date().toISOString()
    };

    passkeys.set(credential.id, passkey);
    
    // Add passkey reference to user
    user.passkeys.push(passkeyId);

    // Clean up challenge
    authChallenges.delete(sessionId);

    console.log('Passkey registered for user:', user.id);

    res.json({
      message: 'Passkey registered successfully',
      passkeyId: passkeyId
    });
  } catch (error) {
    console.error('Passkey registration finish error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Passkey authentication - Generate options
app.post('/api/passkey/authenticate/begin', (req, res) => {
  try {
    const challenge = generateChallenge();
    const sessionId = uuidv4();

    const options = {
      challenge: challenge,
      timeout: 60000,
      rpId: DOMAIN,
      userVerification: "required",
      allowCredentials: Array.from(passkeys.values()).map(pk => ({
        id: pk.credentialId,
        type: "public-key",
        transports: ["internal", "hybrid"]
      }))
    };

    // Store challenge with session ID
    authChallenges.set(sessionId, {
      challenge,
      type: 'authentication',
      created: Date.now()
    });

    res.json({ ...options, sessionId });
  } catch (error) {
    console.error('Passkey auth begin error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Passkey authentication - Verify assertion
app.post('/api/passkey/authenticate/finish', (req, res) => {
  try {
    const { credential, sessionId } = req.body;
    
    if (!sessionId || !authChallenges.has(sessionId)) {
      return res.status(400).json({ error: 'Invalid authentication session' });
    }

    const challengeData = authChallenges.get(sessionId);
    if (challengeData.type !== 'authentication') {
      return res.status(400).json({ error: 'Invalid authentication session' });
    }

    const passkey = passkeys.get(credential.id);
    if (!passkey) {
      return res.status(400).json({ error: 'Passkey not found' });
    }

    // Verify the assertion (simplified - use proper WebAuthn library in production)
    const isValid = verifySignature(
      credential.response.signature,
      credential.response.authenticatorData,
      credential.response.clientDataJSON,
      passkey.publicKey
    );

    if (!isValid) {
      return res.status(400).json({ error: 'Invalid passkey assertion' });
    }

    const user = users.get(passkey.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    // Clean up challenge
    authChallenges.delete(sessionId);

    console.log('Passkey authentication successful for user:', user.id);

    res.json({
      message: 'Passkey authentication successful',
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (error) {
    console.error('Passkey auth finish error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// High-value transaction passkey verification
app.post('/api/passkey/verify-high-value', authenticateToken, (req, res) => {
  try {
    const { credential, sessionId } = req.body;
    
    if (!sessionId || !authChallenges.has(sessionId)) {
      return res.status(400).json({ error: 'Invalid authentication session' });
    }

    const challengeData = authChallenges.get(sessionId);
    if (challengeData.type !== 'high-value') {
      return res.status(400).json({ error: 'Invalid high-value authentication session' });
    }

    const passkey = passkeys.get(credential.id);
    if (!passkey) {
      return res.status(400).json({ error: 'Passkey not found' });
    }

    // Verify this is the same user
    if (passkey.userId !== req.user.id) {
      return res.status(403).json({ error: 'Passkey does not belong to authenticated user' });
    }

    // Verify the assertion for high-value transaction
    const isValid = verifySignature(
      credential.response.signature,
      credential.response.authenticatorData,
      credential.response.clientDataJSON,
      passkey.publicKey
    );

    if (!isValid) {
      return res.status(400).json({ error: 'Invalid high-value transaction authentication' });
    }

    // Parse authenticator data to check for txAuthSimple extension
    try {
      const authData = Buffer.from(credential.response.authenticatorData, 'base64url');
      const extensionsPresent = (authData[32] & 0x80) !== 0; // Check ED flag
      
      if (extensionsPresent) {
        console.log('✅ txAuthSimple extension detected in high-value transaction');
      }
    } catch (parseError) {
      console.log('Could not parse extension data:', parseError.message);
    }

    // Store successful high-value auth for this user session
    const user = users.get(req.user.id);
    if (user) {
      user.highValueAuthTimestamp = Date.now();
      user.highValueAuthValid = true;
    }

    // Clean up challenge
    authChallenges.delete(sessionId);

    console.log('High-value transaction authenticated for user:', req.user.id);

    res.json({
      message: 'High-value transaction authentication successful',
      verified: true,
      timestamp: Date.now()
    });
  } catch (error) {
    console.error('High-value auth error:', error);
    res.status(500).json({ error: 'High-value authentication failed' });
  }
});

// Add high-value auth begin endpoint
app.post('/api/passkey/verify-high-value/begin', authenticateToken, (req, res) => {
  try {
    const { amount } = req.body;
    const user = users.get(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const challenge = generateChallenge();
    const sessionId = uuidv4();

    const options = {
      challenge: challenge,
      timeout: 60000,
      rpId: DOMAIN,
      userVerification: "required",
      allowCredentials: user.passkeys.map(passkeyId => {
        const passkey = Array.from(passkeys.values()).find(pk => pk.id === passkeyId);
        return passkey ? {
          id: passkey.credentialId,
          type: "public-key",
          transports: ["internal", "hybrid"]
        } : null;
      }).filter(Boolean),
      extensions: {
        txAuthSimple: `Authorize purchase of $${amount?.toLocaleString() || 'unknown amount'}`
      }
    };

    // Store challenge with session ID
    authChallenges.set(sessionId, {
      challenge,
      userId: user.id,
      type: 'high-value',
      amount,
      created: Date.now()
    });

    res.json({ ...options, sessionId });
  } catch (error) {
    console.error('High-value auth begin error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add this route to handle favicon requests
app.get('/favicon.ico', (req, res) => {
  res.status(204).end();
});

app.get('/favicon.png', (req, res) => {
  res.status(204).end();
});

// Get all cars
app.get('/api/cars', (req, res) => {
  const carList = Array.from(cars.values());
  
  // Log if AI is accessing cars
  if (req.aiDetection?.isLikelyAI) {
    console.log('🤖 AI accessing car listings:', {
      ip: req.aiDetection.clientIP,
      score: req.aiDetection.score
    });
  }
  
  res.json(carList);
});

// AI Detection endpoint for client-side reporting
app.post('/api/detect-ai', (req, res) => {
  const { clientDetection } = req.body;
  
  // Combine server and client detection
  const combinedDetection = {
    server: req.aiDetection,
    client: clientDetection,
    timestamp: new Date().toISOString()
  };
  
  // Log combined detection
  console.log('🔍 Combined AI Detection Report:', combinedDetection);
  
  // Store detection (in production, save to database)
  global.aiDetections = global.aiDetections || [];
  global.aiDetections.push(combinedDetection);
  
  res.json({
    detected: req.aiDetection?.isLikelyAI || false,
    serverScore: req.aiDetection?.score || 0,
    clientScore: clientDetection?.score || 0,
    combinedScore: (req.aiDetection?.score || 0) + (clientDetection?.score || 0)
  });
});

// Get single car
app.get('/api/cars/:id', (req, res) => {
  const car = cars.get(req.params.id);
  if (!car) {
    return res.status(404).json({ error: 'Car not found' });
  }
  res.json(car);
});

// Add to cart
app.post('/api/cart/add', authenticateToken, (req, res) => {
  try {
    const { carId } = req.body;
    const user = users.get(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const car = cars.get(carId);
    if (!car) {
      return res.status(404).json({ error: 'Car not found' });
    }

    if (!user.cart.includes(carId)) {
      user.cart.push(carId);
    }

    console.log('Added to cart for user:', user.id, 'Car:', carId);

    res.json({ message: 'Car added to cart', cart: user.cart });
  } catch (error) {
    console.error('Add to cart error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get cart
app.get('/api/cart', authenticateToken, (req, res) => {
  try {
    const user = users.get(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const cartCars = user.cart.map(carId => cars.get(carId)).filter(Boolean);
    
    console.log('Cart retrieved for user:', user.id, 'Items:', cartCars.length);
    
    res.json(cartCars);
  } catch (error) {
    console.error('Get cart error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Remove from cart
app.delete('/api/cart/:carId', authenticateToken, (req, res) => {
  try {
    const user = users.get(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.cart = user.cart.filter(id => id !== req.params.carId);
    
    console.log('Removed from cart for user:', user.id, 'Car:', req.params.carId);
    
    res.json({ message: 'Car removed from cart', cart: user.cart });
  } catch (error) {
    console.error('Remove from cart error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create order
app.post('/api/orders', authenticateToken, (req, res) => {
  try {
    const { carIds, customerInfo, paymentInfo, requiresHighValueAuth } = req.body;
    const user = users.get(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const orderCars = carIds.map(id => cars.get(id)).filter(Boolean);
    const total = orderCars.reduce((sum, car) => sum + car.price, 0);

    // ALWAYS require passkey auth for purchases over $50,000, regardless of AI detection
    const isHighValue = total > 50000;
    
    if (isHighValue) {
      // Verify high-value auth was completed recently (within last 5 minutes)
      const authAge = Date.now() - (user.highValueAuthTimestamp || 0);
      const fiveMinutes = 5 * 60 * 1000;
      
      if (!user.highValueAuthValid || authAge > fiveMinutes) {
        return res.status(403).json({ 
          error: 'High-value transaction requires passkey authentication',
          requiresAuth: true,
          amount: total,
          isHighValue: true
        });
      }
      
      // Clear the high-value auth flag after use
      user.highValueAuthValid = false;
      user.highValueAuthTimestamp = null;
    }

    const orderId = uuidv4();
    const order = {
      id: orderId,
      userId: user.id,
      cars: orderCars,
      customerInfo,
      paymentInfo: { ...paymentInfo, cardNumber: '****' + paymentInfo.cardNumber.slice(-4) },
      total,
      status: 'confirmed',
      highValueAuth: isHighValue,
      createdAt: new Date().toISOString()
    };

    orders.set(orderId, order);
    
    // Clear cart
    user.cart = [];

    console.log(`✅ Order created: ${orderId}, Total: $${total.toLocaleString()}${order.highValueAuth ? ' (High-value with passkey auth)' : ''}`);

    res.status(201).json({
      message: 'Order created successfully',
      orderId,
      total,
      highValueAuth: order.highValueAuth
    });
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user orders
app.get('/api/orders', authenticateToken, (req, res) => {
  try {
    const userOrders = Array.from(orders.values()).filter(order => order.userId === req.user.id);
    res.json(userOrders);
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Debug endpoint to check storage state
app.get('/api/debug/users', (req, res) => {
  res.json({
    totalUsers: users.size,
    emailMappings: Array.from(usersByEmail.entries()),
    users: Array.from(users.entries()).map(([id, user]) => ({
      id,
      email: user.email,
      name: user.name,
      hasPassword: !!user.password,
      passwordLength: user.password ? user.password.length : 0,
      cartItems: user.cart ? user.cart.length : 0,
      passkeys: user.passkeys ? user.passkeys.length : 0
    }))
  });
});

// Get user profile
app.get('/api/profile', authenticateToken, (req, res) => {
  try {
    const user = users.get(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userPasskeys = user.passkeys.map(passkeyId => {
      const passkey = Array.from(passkeys.values()).find(pk => pk.id === passkeyId);
      return passkey ? { id: passkey.id, createdAt: passkey.createdAt } : null;
    }).filter(Boolean);

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      passkeys: userPasskeys,
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Environment:', process.env.NODE_ENV || 'development');
  console.log('Domain:', DOMAIN);
  console.log('Allowed origins:', CLIENT_ORIGINS);
  console.log('Sample cars loaded:', cars.size);
  console.log('Users storage initialized');
  
  // Debug: Log storage state periodically
  setInterval(() => {
    console.log('=== STORAGE DEBUG ===');
    console.log('Total users:', users.size);
    console.log('Email mappings:', Array.from(usersByEmail.entries()));
    console.log('Users data:', Array.from(users.entries()).map(([id, user]) => ({ 
      id, 
      email: user.email, 
      name: user.name 
    })));
    console.log('===================');
  }, 30000); // Log every 30 seconds
});

// Export for testing
module.exports = app;
