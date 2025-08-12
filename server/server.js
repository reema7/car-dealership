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

// Middleware
// In server/server.js, replace CORS with:
app.use(cors({
  origin: '*', // Allows all origins - for testing only!
  credentials: false // Must be false when using wildcard
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
const users = new Map();
const cars = new Map();
const orders = new Map();
const passkeys = new Map(); // Store passkey credentials

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

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// User registration
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (users.has(email)) {
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
      createdAt: new Date().toISOString()
    };

    users.set(email, user);

    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: userId, email, name }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.get(email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, email, name: user.name }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Passkey registration - Generate options
app.post('/api/passkey/register/begin', authenticateToken, (req, res) => {
  try {
    const user = Array.from(users.values()).find(u => u.id === req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const challenge = generateChallenge();
    const userId = Buffer.from(user.id).toString('base64url');

    const options = {
      rp: {
        name: "AutoDealer Pro",
        id: "localhost" // Change to your domain in production
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

    // Store challenge temporarily (use Redis or similar in production)
    user.currentChallenge = challenge;

    res.json(options);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Passkey registration - Verify credential
app.post('/api/passkey/register/finish', authenticateToken, (req, res) => {
  try {
    const { credential } = req.body;
    const user = Array.from(users.values()).find(u => u.id === req.user.id);
    
    if (!user || !user.currentChallenge) {
      return res.status(400).json({ error: 'Invalid registration session' });
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
    if (!user.passkeys) user.passkeys = [];
    user.passkeys.push(passkeyId);

    delete user.currentChallenge;

    res.json({
      message: 'Passkey registered successfully',
      passkeyId: passkeyId
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Passkey authentication - Generate options
app.post('/api/passkey/authenticate/begin', (req, res) => {
  try {
    const challenge = generateChallenge();

    const options = {
      challenge: challenge,
      timeout: 60000,
      rpId: "localhost", // Change to your domain in production
      userVerification: "required",
      allowCredentials: Array.from(passkeys.values()).map(pk => ({
        id: pk.credentialId,
        type: "public-key",
        transports: ["internal", "hybrid"]
      }))
    };

    // Store challenge temporarily
    global.currentAuthChallenge = challenge;

    res.json(options);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Passkey authentication - Verify assertion
app.post('/api/passkey/authenticate/finish', (req, res) => {
  try {
    const { credential } = req.body;
    
    if (!global.currentAuthChallenge) {
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

    const user = Array.from(users.values()).find(u => u.id === passkey.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    delete global.currentAuthChallenge;

    res.json({
      message: 'Passkey authentication successful',
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// High-value transaction passkey verification
app.post('/api/passkey/verify-high-value', authenticateToken, (req, res) => {
  try {
    const { credential } = req.body;
    
    if (!global.currentAuthChallenge) {
      return res.status(400).json({ error: 'Invalid authentication session' });
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
        // In a production implementation, you would parse the CBOR extension data here
      }
    } catch (parseError) {
      console.log('Could not parse extension data:', parseError.message);
    }

    // Store successful high-value auth for this user session
    const user = Array.from(users.values()).find(u => u.id === req.user.id);
    if (user) {
      user.highValueAuthTimestamp = Date.now();
      user.highValueAuthValid = true;
    }

    delete global.currentAuthChallenge;

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

// Add this route to handle favicon requests
app.get('/favicon.ico', (req, res) => {
  res.status(204).end(); // No content response
});

app.get('/favicon.png', (req, res) => {
  res.status(204).end(); // No content response
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
    const user = Array.from(users.values()).find(u => u.id === req.user.id);
    
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

    res.json({ message: 'Car added to cart', cart: user.cart });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get cart
app.get('/api/cart', authenticateToken, (req, res) => {
  try {
    const user = Array.from(users.values()).find(u => u.id === req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const cartCars = user.cart.map(carId => cars.get(carId)).filter(Boolean);
    res.json(cartCars);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Remove from cart
app.delete('/api/cart/:carId', authenticateToken, (req, res) => {
  try {
    const user = Array.from(users.values()).find(u => u.id === req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.cart = user.cart.filter(id => id !== req.params.carId);
    res.json({ message: 'Car removed from cart', cart: user.cart });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create order
app.post('/api/orders', authenticateToken, (req, res) => {
  try {
    const { carIds, customerInfo, paymentInfo, requiresHighValueAuth } = req.body;
    const user = Array.from(users.values()).find(u => u.id === req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const orderCars = carIds.map(id => cars.get(id)).filter(Boolean);
    const total = orderCars.reduce((sum, car) => sum + car.price, 0);

    // Check for high-value transaction authentication
    if (requiresHighValueAuth && total > 50000) {
      // Verify high-value auth was completed recently (within last 5 minutes)
      const authAge = Date.now() - (user.highValueAuthTimestamp || 0);
      const fiveMinutes = 5 * 60 * 1000;
      
      if (!user.highValueAuthValid || authAge > fiveMinutes) {
        return res.status(403).json({ 
          error: 'High-value transaction requires recent passkey authentication',
          requiresAuth: true,
          amount: total
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
      highValueAuth: requiresHighValueAuth && total > 50000,
      createdAt: new Date().toISOString()
    };

    orders.set(orderId, order);
    
    // Clear cart
    user.cart = [];

    console.log(`✅ Order created: ${orderId}, Total: ${total}${order.highValueAuth ? ' (High-value with passkey auth)' : ''}`);

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
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user profile
app.get('/api/profile', authenticateToken, (req, res) => {
  try {
    const user = Array.from(users.values()).find(u => u.id === req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userPasskeys = user.passkeys ? user.passkeys.map(pkId => {
      const passkey = Array.from(passkeys.values()).find(pk => pk.id === pkId);
      return passkey ? { id: passkey.id, createdAt: passkey.createdAt } : null;
    }).filter(Boolean) : [];

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      passkeys: userPasskeys,
      createdAt: user.createdAt
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Sample cars loaded:', cars.size);
});

// Export for testing
module.exports = app;
