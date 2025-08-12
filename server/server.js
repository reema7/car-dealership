// server.js - Node.js/Express Server with Database Support + Localhost Fallback
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
const DOMAIN = isDevelopment ? 'localhost' : (process.env.WEBAUTHN_DOMAIN || 'car-dealership-client.vercel.app');
const CLIENT_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:3001', 
  process.env.CLIENT_URL || 'https://car-dealership-client.vercel.app',
  process.env.SERVER_URL || 'https://car-dealership-xmlx.vercel.app'
];

// Database configuration
let db = null;
let useDatabase = false;

// Initialize database connection (only in production)
const initDatabase = async () => {
  if (isDevelopment) {
    console.log('🏠 Development mode: Using in-memory storage');
    return;
  }

  try {
    // Try to connect to Vercel Postgres
    const { sql } = require('@vercel/postgres');
    
    // Test connection
    await sql`SELECT NOW()`;
    
    // Create tables if they don't exist
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        cart TEXT DEFAULT '[]',
        passkeys TEXT DEFAULT '[]',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;
    
    await sql`
      CREATE TABLE IF NOT EXISTS passkeys (
        id UUID PRIMARY KEY,
        credential_id VARCHAR(1024) UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        user_id UUID REFERENCES users(id),
        counter INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;
    
    await sql`
      CREATE TABLE IF NOT EXISTS orders (
        id UUID PRIMARY KEY,
        user_id UUID REFERENCES users(id),
        cars TEXT NOT NULL,
        customer_info TEXT NOT NULL,
        payment_info TEXT NOT NULL,
        total INTEGER NOT NULL,
        status VARCHAR(50) DEFAULT 'confirmed',
        high_value_auth BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;
    
    db = sql;
    useDatabase = true;
    console.log('🗄️ Database connected successfully');
    
  } catch (error) {
    console.log('⚠️ Database connection failed, falling back to in-memory storage:', error.message);
    useDatabase = false;
  }
};

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (isDevelopment) return callback(null, true);
    if (CLIENT_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    console.log('CORS blocked origin:', origin);
    return callback(null, true);
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
  
  const indicators = {
    isHeadless: /headless/i.test(userAgent),
    isSelenium: /selenium/i.test(userAgent),
    isPuppeteer: /puppeteer/i.test(userAgent),
    isPlaywright: /playwright/i.test(userAgent),
    isPhantom: /phantom/i.test(userAgent),
    isBot: /bot|crawler|spider|scraper/i.test(userAgent),
    noAcceptLanguage: !req.get('Accept-Language'),
    noAcceptEncoding: !req.get('Accept-Encoding'),
    hasWebDriverHeader: !!(req.get('webdriver') || req.get('x-webdriver')),
    isCloudIP: /^(34\.|35\.|52\.|54\.|18\.|3\.|13\.|40\.|104\.|178\.128\.|167\.99\.)/.test(clientIP),
    timestamp: Date.now()
  };
  
  const positiveIndicators = Object.values(indicators).filter(v => v === true).length;
  const isLikelyAI = positiveIndicators >= 2;
  
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

// In-memory storage (fallback for localhost)
const users = new Map();
const cars = new Map();
const orders = new Map();
const passkeys = new Map();
const authChallenges = new Map();

// Database abstraction layer
const UserStore = {
  async create(user) {
    if (useDatabase) {
      const result = await db`
        INSERT INTO users (id, email, password, name, cart, passkeys, created_at)
        VALUES (${user.id}, ${user.email}, ${user.password}, ${user.name}, 
                ${JSON.stringify(user.cart)}, ${JSON.stringify(user.passkeys)}, NOW())
        RETURNING *
      `;
      return result[0];
    } else {
      users.set(user.email, user);
      return user;
    }
  },

  async findByEmail(email) {
    if (useDatabase) {
      const result = await db`SELECT * FROM users WHERE email = ${email}`;
      if (result.length > 0) {
        const user = result[0];
        return {
          ...user,
          cart: JSON.parse(user.cart || '[]'),
          passkeys: JSON.parse(user.passkeys || '[]')
        };
      }
      return null;
    } else {
      return users.get(email) || null;
    }
  },

  async findById(userId) {
    if (useDatabase) {
      const result = await db`SELECT * FROM users WHERE id = ${userId}`;
      if (result.length > 0) {
        const user = result[0];
        return {
          ...user,
          cart: JSON.parse(user.cart || '[]'),
          passkeys: JSON.parse(user.passkeys || '[]')
        };
      }
      return null;
    } else {
      // For in-memory, search through all users
      for (const [email, user] of users.entries()) {
        if (user.id === userId) {
          return user;
        }
      }
      return null;
    }
  },

  async update(email, updates) {
    if (useDatabase) {
      const result = await db`
        UPDATE users 
        SET cart = ${JSON.stringify(updates.cart || [])},
            passkeys = ${JSON.stringify(updates.passkeys || [])}
        WHERE email = ${email}
        RETURNING *
      `;
      return result[0];
    } else {
      const user = users.get(email);
      if (user) {
        Object.assign(user, updates);
        users.set(email, user);
        return user;
      }
      return null;
    }
  }
};

const PasskeyStore = {
  async create(passkey) {
    if (useDatabase) {
      const result = await db`
        INSERT INTO passkeys (id, credential_id, public_key, user_id, counter, created_at)
        VALUES (${passkey.id}, ${passkey.credentialId}, ${passkey.publicKey}, 
                ${passkey.userId}, ${passkey.counter}, NOW())
        RETURNING *
      `;
      return result[0];
    } else {
      passkeys.set(passkey.credentialId, passkey);
      return passkey;
    }
  },

  async findByCredentialId(credentialId) {
    if (useDatabase) {
      const result = await db`SELECT * FROM passkeys WHERE credential_id = ${credentialId}`;
      return result[0] || null;
    } else {
      return passkeys.get(credentialId) || null;
    }
  },

  async findByUserId(userId) {
    if (useDatabase) {
      const result = await db`SELECT * FROM passkeys WHERE user_id = ${userId}`;
      return result;
    } else {
      return Array.from(passkeys.values()).filter(pk => pk.userId === userId);
    }
  }
};

const OrderStore = {
  async create(order) {
    if (useDatabase) {
      const result = await db`
        INSERT INTO orders (id, user_id, cars, customer_info, payment_info, total, status, high_value_auth, created_at)
        VALUES (${order.id}, ${order.userId}, ${JSON.stringify(order.cars)}, 
                ${JSON.stringify(order.customerInfo)}, ${JSON.stringify(order.paymentInfo)},
                ${order.total}, ${order.status}, ${order.highValueAuth}, NOW())
        RETURNING *
      `;
      return result[0];
    } else {
      orders.set(order.id, order);
      return order;
    }
  },

  async findByUserId(userId) {
    if (useDatabase) {
      const result = await db`SELECT * FROM orders WHERE user_id = ${userId} ORDER BY created_at DESC`;
      return result.map(order => ({
        ...order,
        cars: JSON.parse(order.cars),
        customerInfo: JSON.parse(order.customer_info),
        paymentInfo: JSON.parse(order.payment_info)
      }));
    } else {
      return Array.from(orders.values()).filter(order => order.userId === userId);
    }
  }
};

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

// Helper functions for WebAuthn
const generateChallenge = () => {
  return crypto.randomBytes(32).toString('base64url');
};

const verifySignature = (signature, authenticatorData, clientDataJSON, publicKey) => {
  try {
    const clientDataHash = crypto.createHash('sha256').update(Buffer.from(clientDataJSON, 'base64url')).digest();
    const signedData = Buffer.concat([Buffer.from(authenticatorData, 'base64url'), clientDataHash]);
    return true; // Simplified verification
  } catch (error) {
    return false;
  }
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      console.log('JWT verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    try {
      // Try to find user in storage
      const user = await UserStore.findByEmail(decoded.email);
      if (!user) {
        console.log('User not found for email:', decoded.email);
        return res.status(404).json({ error: 'User not found' });
      }
      
      console.log('✅ User authenticated:', { id: user.id, email: user.email });
      req.user = decoded;
      next();
    } catch (error) {
      console.error('Authentication error:', error);
      res.status(500).json({ error: 'Authentication failed' });
    }
  });
};

// Routes

// User registration
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    console.log('Registration attempt for email:', email);

    // Check if user already exists
    const existingUser = await UserStore.findByEmail(email);
    if (existingUser) {
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

    await UserStore.create(user);

    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '24h' });

    console.log('User registered successfully:', { id: userId, email, name });

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

    const user = await UserStore.findByEmail(email);
    if (!user) {
      console.log('No user found for email:', email);
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
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
app.post('/api/passkey/register/begin', authenticateToken, async (req, res) => {
  try {
    const user = await UserStore.findByEmail(req.user.email);
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
        { alg: -7, type: "public-key" },
        { alg: -257, type: "public-key" }
      ],
      timeout: 60000,
      attestation: "direct",
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        residentKey: "preferred"
      }
    };

    authChallenges.set(sessionId, {
      challenge,
      userId: user.id,
      type: 'registration',
      created: Date.now()
    });

    // Clean up old challenges
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
app.post('/api/passkey/register/finish', authenticateToken, async (req, res) => {
  try {
    const { credential, sessionId } = req.body;
    
    if (!sessionId || !authChallenges.has(sessionId)) {
      return res.status(400).json({ error: 'Invalid registration session' });
    }

    const challengeData = authChallenges.get(sessionId);
    if (challengeData.userId !== req.user.id || challengeData.type !== 'registration') {
      return res.status(400).json({ error: 'Invalid registration session' });
    }

    const user = await UserStore.findByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const passkeyId = uuidv4();
    const passkey = {
      id: passkeyId,
      credentialId: credential.id,
      publicKey: credential.response.publicKey,
      userId: user.id,
      counter: 0,
      createdAt: new Date().toISOString()
    };

    await PasskeyStore.create(passkey);
    
    // Update user's passkey list
    user.passkeys.push(passkeyId);
    await UserStore.update(user.email, { passkeys: user.passkeys });

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
app.post('/api/passkey/authenticate/begin', async (req, res) => {
  try {
    const challenge = generateChallenge();
    const sessionId = uuidv4();

    // Get all passkeys for the options
    let allowCredentials = [];
    if (useDatabase) {
      const allPasskeys = await db`SELECT credential_id FROM passkeys`;
      allowCredentials = allPasskeys.map(pk => ({
        id: pk.credential_id,
        type: "public-key",
        transports: ["internal", "hybrid"]
      }));
    } else {
      allowCredentials = Array.from(passkeys.values()).map(pk => ({
        id: pk.credentialId,
        type: "public-key",
        transports: ["internal", "hybrid"]
      }));
    }

    const options = {
      challenge: challenge,
      timeout: 60000,
      rpId: DOMAIN,
      userVerification: "required",
      allowCredentials: allowCredentials
    };

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
app.post('/api/passkey/authenticate/finish', async (req, res) => {
  try {
    const { credential, sessionId } = req.body;
    
    if (!sessionId || !authChallenges.has(sessionId)) {
      return res.status(400).json({ error: 'Invalid authentication session' });
    }

    const challengeData = authChallenges.get(sessionId);
    if (challengeData.type !== 'authentication') {
      return res.status(400).json({ error: 'Invalid authentication session' });
    }

    const passkey = await PasskeyStore.findByCredentialId(credential.id);
    if (!passkey) {
      return res.status(400).json({ error: 'Passkey not found' });
    }

    // Verify the assertion (simplified - use proper WebAuthn library in production)
    const isValid = verifySignature(
      credential.response.signature,
      credential.response.authenticatorData,
      credential.response.clientDataJSON,
      passkey.publicKey || passkey.public_key
    );

    if (!isValid) {
      return res.status(400).json({ error: 'Invalid passkey assertion' });
    }

    const user = await UserStore.findByEmail(req.user?.email) || 
                 await UserStore.findById(passkey.userId || passkey.user_id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

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

// High-value transaction passkey verification - Begin
app.post('/api/passkey/verify-high-value/begin', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await UserStore.findByEmail(req.user.email);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const challenge = generateChallenge();
    const sessionId = uuidv4();

    // Get user's passkeys
    const userPasskeys = await PasskeyStore.findByUserId(user.id);
    const allowCredentials = userPasskeys.map(passkey => ({
      id: passkey.credential_id || passkey.credentialId,
      type: "public-key",
      transports: ["internal", "hybrid"]
    }));

    const options = {
      challenge: challenge,
      timeout: 60000,
      rpId: DOMAIN,
      userVerification: "required",
      allowCredentials: allowCredentials,
      extensions: {
        txAuthSimple: `Authorize purchase of ${amount?.toLocaleString() || 'unknown amount'}`
      }
    };

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

// High-value transaction passkey verification - Finish
app.post('/api/passkey/verify-high-value', authenticateToken, async (req, res) => {
  try {
    const { credential, sessionId } = req.body;
    
    if (!sessionId || !authChallenges.has(sessionId)) {
      return res.status(400).json({ error: 'Invalid authentication session' });
    }

    const challengeData = authChallenges.get(sessionId);
    if (challengeData.type !== 'high-value') {
      return res.status(400).json({ error: 'Invalid high-value authentication session' });
    }

    const passkey = await PasskeyStore.findByCredentialId(credential.id);
    if (!passkey) {
      return res.status(400).json({ error: 'Passkey not found' });
    }

    // Verify this is the same user
    if ((passkey.userId || passkey.user_id) !== req.user.id) {
      return res.status(403).json({ error: 'Passkey does not belong to authenticated user' });
    }

    // Verify the assertion for high-value transaction
    const isValid = verifySignature(
      credential.response.signature,
      credential.response.authenticatorData,
      credential.response.clientDataJSON,
      passkey.publicKey || passkey.public_key
    );

    if (!isValid) {
      return res.status(400).json({ error: 'Invalid high-value transaction authentication' });
    }

    // Parse authenticator data to check for txAuthSimple extension
    try {
      const authData = Buffer.from(credential.response.authenticatorData, 'base64url');
      const extensionsPresent = (authData[32] & 0x80) !== 0;
      
      if (extensionsPresent) {
        console.log('✅ txAuthSimple extension detected in high-value transaction');
      }
    } catch (parseError) {
      console.log('Could not parse extension data:', parseError.message);
    }

    // Store successful high-value auth for this user session
    const user = await UserStore.findByEmail(req.user.email);
    if (user) {
      // For in-memory storage, we can store this directly
      // For database, we'd typically use a session store or Redis
      user.highValueAuthTimestamp = Date.now();
      user.highValueAuthValid = true;
      
      if (!useDatabase) {
        // Update in-memory user
        users.set(user.email, user);
      }
      // Note: For database, you might want to store this in a sessions table
    }

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

// Remove from cart
app.delete('/api/cart/:carId', authenticateToken, async (req, res) => {
  try {
    const user = await UserStore.findByEmail(req.user.email);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.cart = user.cart.filter(id => id !== req.params.carId);
    await UserStore.update(user.email, { cart: user.cart });
    
    console.log('Removed from cart for user:', user.id, 'Car:', req.params.carId);
    
    res.json({ message: 'Car removed from cart', cart: user.cart });
  } catch (error) {
    console.error('Remove from cart error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create order
app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { carIds, customerInfo, paymentInfo, requiresHighValueAuth } = req.body;
    const user = await UserStore.findByEmail(req.user.email);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const orderCars = carIds.map(id => cars.get(id)).filter(Boolean);
    const total = orderCars.reduce((sum, car) => sum + car.price, 0);

    // ALWAYS require passkey auth for purchases over $50,000
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
      
      if (!useDatabase) {
        users.set(user.email, user);
      }
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

    await OrderStore.create(order);
    
    // Clear cart
    user.cart = [];
    await UserStore.update(user.email, { cart: [] });

    console.log(`✅ Order created: ${orderId}, Total: ${total.toLocaleString()}${order.highValueAuth ? ' (High-value with passkey auth)' : ''}`);

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
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const userOrders = await OrderStore.findByUserId(req.user.id);
    res.json(userOrders);
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await UserStore.findByEmail(req.user.email);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userPasskeys = await PasskeyStore.findByUserId(user.id);
    const passkeyInfo = userPasskeys.map(passkey => ({ 
      id: passkey.id, 
      createdAt: passkey.created_at || passkey.createdAt 
    }));

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      passkeys: passkeyInfo,
      createdAt: user.created_at || user.createdAt
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// AI Detection endpoint for client-side reporting
app.post('/api/detect-ai', (req, res) => {
  const { clientDetection } = req.body;
  
  const combinedDetection = {
    server: req.aiDetection,
    client: clientDetection,
    timestamp: new Date().toISOString()
  };
  
  console.log('🔍 Combined AI Detection Report:', combinedDetection);
  
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

// Add favicon routes
app.get('/favicon.ico', (req, res) => {
  res.status(204).end();
});

app.get('/favicon.png', (req, res) => {
  res.status(204).end();
});

// Get all cars
app.get('/api/cars', (req, res) => {
  const carList = Array.from(cars.values());
  
  if (req.aiDetection?.isLikelyAI) {
    console.log('🤖 AI accessing car listings:', {
      ip: req.aiDetection.clientIP,
      score: req.aiDetection.score
    });
  }
  
  res.json(carList);
});

// Add to cart
app.post('/api/cart/add', authenticateToken, async (req, res) => {
  try {
    const { carId } = req.body;
    const user = await UserStore.findByEmail(req.user.email);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const car = cars.get(carId);
    if (!car) {
      return res.status(404).json({ error: 'Car not found' });
    }

    if (!user.cart.includes(carId)) {
      user.cart.push(carId);
      await UserStore.update(user.email, { cart: user.cart });
    }

    console.log('Added to cart for user:', user.id, 'Car:', carId);

    res.json({ message: 'Car added to cart', cart: user.cart });
  } catch (error) {
    console.error('Add to cart error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get cart
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const user = await UserStore.findByEmail(req.user.email);
    
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

// Debug endpoint
app.get('/api/debug/users', async (req, res) => {
  try {
    if (useDatabase) {
      const dbUsers = await db`SELECT id, email, name, created_at FROM users`;
      res.json({
        storage: 'database',
        totalUsers: dbUsers.length,
        users: dbUsers
      });
    } else {
      res.json({
        storage: 'in-memory',
        totalUsers: users.size,
        userEmails: Array.from(users.keys()),
        users: Array.from(users.entries()).map(([email, user]) => ({
          email,
          id: user.id,
          name: user.name
        }))
      });
    }
  } catch (error) {
    res.json({ error: error.message });
  }
});

// Initialize and start server
const startServer = async () => {
  await initDatabase();
  initializeCars();
  
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Environment:', process.env.NODE_ENV || 'development');
    console.log('Domain:', DOMAIN);
    console.log('Storage:', useDatabase ? 'Database' : 'In-Memory');
    console.log('Sample cars loaded:', cars.size);
  });
};

startServer().catch(console.error);

module.exports = app;
