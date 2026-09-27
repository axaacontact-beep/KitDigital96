require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const admin = require('firebase-admin');
const Razorpay = require('razorpay');

// --------------------------------------------------
// FIREBASE ADMIN SDK INITIALIZATION
// --------------------------------------------------
if (!admin.apps.length) {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    // 1. Agar poora JSON string diya gaya ho
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  } else if (
    process.env.FIREBASE_PROJECT_ID &&
    process.env.FIREBASE_CLIENT_EMAIL &&
    process.env.FIREBASE_PRIVATE_KEY
  ) {
    // 2. Agar Vercel / Render par alag-alag variables set kiye ho
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
      })
    });
  } else {
    // 3. Fallback: Default Google Application Credentials
    admin.initializeApp({
      credential: admin.credential.applicationDefault()
    });
  }
}

const db = admin.firestore();

// --------------------------------------------------
// RAZORPAY INITIALIZATION
// --------------------------------------------------
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || '',
  key_secret: process.env.RAZORPAY_KEY_SECRET || ''
});

// --------------------------------------------------
// EXPRESS APP & MIDDLEWARE SETUP
// --------------------------------------------------
const app = express();

app.use(cors({ origin: true }));

// Express JSON parser with raw body buffer preservation for Razorpay webhook verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// --------------------------------------------------
// AUTHENTICATION MIDDLEWARE
// --------------------------------------------------
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Unauthorized: Missing or invalid token format' });
    }

    const idToken = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    
    // Attach validated user token data (UID is the sole user identity)
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Authentication Error:', error);
    return res.status(401).json({ success: false, error: 'Unauthorized: Invalid Firebase ID token' });
  }
};

// --------------------------------------------------
// ADMIN AUTHORIZATION HELPER
// --------------------------------------------------
const requireAdmin = async (req, res, next) => {
  try {
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    if (!userDoc.exists || userDoc.data().role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Forbidden: Admin privilege required' });
    }
    next();
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Failed to verify admin status' });
  }
};

// Helper function to generate unique referral code if missing
const generateReferralCode = () => {
  return 'KIT' + crypto.randomBytes(4).toString('hex').toUpperCase();
};

// ==================================================
// API ENDPOINTS
// ==================================================

// --------------------------------------------------
// 1. POST /auth/signup
// --------------------------------------------------
app.post('/auth/signup', authenticateUser, async (req, res) => {
  try {
    const { uid, username, email, referralCode } = req.body;
    const authUid = req.user.uid;

    if (uid && uid !== authUid) {
      return res.status(403).json({ success: false, error: 'Forbidden: UID mismatch with token' });
    }

    const userRef = db.collection('users').doc(authUid);
    const userDoc = await userRef.get();

    if (userDoc.exists) {
      return res.status(200).json({ 
        success: true, 
        message: 'User already exists', 
        user: userDoc.data() 
      });
    }

    const finalReferralCode = referralCode || generateReferralCode();
    let referredBy = null;

    if (req.body.referredByCode) {
      const referrerQuery = await db.collection('users')
        .where('referralCode', '==', req.body.referredByCode)
        .limit(1)
        .get();

      if (!referrerQuery.empty) {
        referredBy = referrerQuery.docs[0].id;
      }
    }

    const newUser = {
      username: username || req.user.name || 'User',
      email: email || req.user.email || '',
      wallet: 0,
      purchasedProducts: [],
      referralCode: finalReferralCode,
      referredBy: referredBy || null,
      role: 'user',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    await userRef.set(newUser);

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: newUser
    });
  } catch (error) {
    console.error('Signup Endpoint Error:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// 2. POST /payment/createOrder
// --------------------------------------------------
app.post('/payment/createOrder', authenticateUser, async (req, res) => {
  try {
    const { amount } = req.body;
    const userId = req.user.uid;

    if (!amount || typeof amount !== 'number' || amount <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid or missing amount' });
    }

    const amountInPaise = Math.round(amount * 100);

    const options = {
      amount: amountInPaise,
      currency: 'INR',
      receipt: `rcpt_${userId.substring(0, 8)}_${Date.now()}`
    };

    const razorpayOrder = await razorpay.orders.create(options);

    const transactionRef = db.collection('transactions').doc();
    await transactionRef.set({
      transactionId: transactionRef.id,
      userId: userId,
      type: 'deposit',
      amount: amount,
      status: 'PENDING',
      razorpayOrderId: razorpayOrder.id,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.status(200).json({
      success: true,
      order: {
        id: razorpayOrder.id,
        amount: razorpayOrder.amount,
        currency: razorpayOrder.currency,
        key: process.env.RAZORPAY_KEY_ID
      }
    });
  } catch (error) {
    console.error('Create Order Error:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// 3. POST /webhook/razorpay
// --------------------------------------------------
app.post('/webhook/razorpay', async (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

    if (!signature || !webhookSecret) {
      return res.status(400).json({ success: false, error: 'Signature or secret unconfigured' });
    }

    const expectedSignature = crypto
      .createHmac('sha256', webhookSecret)
      .update(req.rawBody)
      .digest('hex');

    if (signature !== expectedSignature) {
      return res.status(400).json({ success: false, error: 'Invalid Razorpay webhook signature' });
    }

    const event = req.body.event;
    const payload = req.body.payload;

    if (event === 'payment.captured') {
      const paymentEntity = payload.payment.entity;
      const razorpayOrderId = paymentEntity.order_id;

      const txnQuery = await db.collection('transactions')
        .where('razorpayOrderId', '==', razorpayOrderId)
        .limit(1)
        .get();

      if (txnQuery.empty) {
        return res.status(404).json({ success: false, error: 'Associated transaction record not found' });
      }

      const txnDoc = txnQuery.docs[0];
      const txnRef = txnDoc.ref;

      await db.runTransaction(async (transaction) => {
        const currentTxnDoc = await transaction.get(txnRef);

        if (!currentTxnDoc.exists) {
          throw new Error('Transaction record missing');
        }

        const txnData = currentTxnDoc.data();

        if (txnData.status === 'SUCCESS') {
          return;
        }

        if (txnData.status !== 'PENDING') {
          throw new Error(`Invalid status transition from state: ${txnData.status}`);
        }

        const userRef = db.collection('users').doc(txnData.userId);
        const userDoc = await transaction.get(userRef);

        if (!userDoc.exists) {
          throw new Error('Target user account not found');
        }

        transaction.update(txnRef, {
          status: 'SUCCESS',
          razorpayPaymentId: paymentEntity.id,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        const currentWallet = userDoc.data().wallet || 0;
        transaction.update(userRef, {
          wallet: currentWallet + txnData.amount
        });
      });

    } else if (event === 'payment.failed') {
      const paymentEntity = payload.payment.entity;
      const razorpayOrderId = paymentEntity.order_id;

      const txnQuery = await db.collection('transactions')
        .where('razorpayOrderId', '==', razorpayOrderId)
        .limit(1)
        .get();

      if (!txnQuery.empty) {
        const txnRef = txnQuery.docs[0].ref;
        await txnRef.update({
          status: 'FAILED',
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
    }

    return res.status(200).json({ status: 'ok' });
  } catch (error) {
    console.error('Webhook Verification Error:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// 4. POST /product/purchase
// --------------------------------------------------
app.post('/product/purchase', authenticateUser, async (req, res) => {
  try {
    const { productId } = req.body;
    const userId = req.user.uid;

    if (!productId || typeof productId !== 'string') {
      return res.status(400).json({ success: false, error: 'Valid Product ID is required' });
    }

    const productRef = db.collection('products').doc(productId);
    const userRef = db.collection('users').doc(userId);

    await db.runTransaction(async (transaction) => {
      const productDoc = await transaction.get(productRef);
      const userDoc = await transaction.get(userRef);

      if (!productDoc.exists) {
        throw new Error('Product not found');
      }

      if (!userDoc.exists) {
        throw new Error('User not found');
      }

      const productData = productDoc.data();
      const userData = userDoc.data();

      if (productData.status !== 'active') {
        throw new Error('Product is currently inactive');
      }

      const purchasedProducts = userData.purchasedProducts || [];
      if (purchasedProducts.includes(productId)) {
        throw new Error('Product already purchased');
      }

      const productPrice = productData.price || 0;
      const userWallet = userData.wallet || 0;

      if (userWallet < productPrice) {
        throw new Error('Insufficient wallet balance');
      }

      transaction.update(userRef, {
        wallet: userWallet - productPrice,
        purchasedProducts: admin.firestore.FieldValue.arrayUnion(productId)
      });

      const currentSales = productData.totalSales || 0;
      transaction.update(productRef, {
        totalSales: currentSales + 1
      });

      const purchaseRef = db.collection('purchases').doc();
      transaction.set(purchaseRef, {
        userId: userId,
        productId: productId,
        amountPaid: productPrice,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });

      const transactionRef = db.collection('transactions').doc();
      transaction.set(transactionRef, {
        transactionId: transactionRef.id,
        userId: userId,
        type: 'purchase',
        amount: productPrice,
        status: 'SUCCESS',
        productId: productId,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    return res.status(200).json({ success: true, message: 'Product purchased successfully' });
  } catch (error) {
    console.error('Purchase Transaction Error:', error);
    return res.status(400).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// 5. POST /product/access
// --------------------------------------------------
app.post('/product/access', authenticateUser, async (req, res) => {
  try {
    const { productId } = req.body;
    const userId = req.user.uid;

    if (!productId) {
      return res.status(400).json({ success: false, error: 'Product ID is required' });
    }

    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({ success: false, error: 'User account not found' });
    }

    const userData = userDoc.data();
    const purchasedProducts = userData.purchasedProducts || [];

    if (!purchasedProducts.includes(productId)) {
      return res.status(403).json({ success: false, error: 'Access denied: Product not purchased' });
    }

    const productDoc = await db.collection('products').doc(productId).get();
    if (!productDoc.exists) {
      return res.status(404).json({ success: false, error: 'Product not found' });
    }

    const productData = productDoc.data();

    return res.status(200).json({
      success: true,
      product: {
        id: productDoc.id,
        title: productData.title,
        description: productData.description,
        downloadUrl: productData.downloadUrl,
        thumbnailUrl: productData.thumbnailUrl
      }
    });
  } catch (error) {
    console.error('Access Verification Error:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// 6. POST /wallet/withdraw
// --------------------------------------------------
app.post('/wallet/withdraw', authenticateUser, async (req, res) => {
  try {
    const { amount, upiId } = req.body;
    const userId = req.user.uid;

    if (!amount || typeof amount !== 'number' || amount <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid withdrawal amount' });
    }

    if (!upiId || typeof upiId !== 'string' || !upiId.trim()) {
      return res.status(400).json({ success: false, error: 'Valid UPI ID is required' });
    }

    const userRef = db.collection('users').doc(userId);

    await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        throw new Error('User account not found');
      }

      const userData = userDoc.data();
      const currentWallet = userData.wallet || 0;

      if (currentWallet < amount) {
        throw new Error('Insufficient wallet balance for withdrawal');
      }

      transaction.update(userRef, {
        wallet: currentWallet - amount
      });

      const transactionRef = db.collection('transactions').doc();
      transaction.set(transactionRef, {
        transactionId: transactionRef.id,
        userId: userId,
        type: 'withdraw',
        amount: amount,
        upiId: upiId.trim(),
        status: 'PENDING',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    return res.status(200).json({
      success: true,
      message: 'Withdrawal request created successfully'
    });
  } catch (error) {
    console.error('Withdrawal Transaction Error:', error);
    return res.status(400).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// 7. POST /admin/product/create
// --------------------------------------------------
app.post('/admin/product/create', authenticateUser, requireAdmin, async (req, res) => {
  try {
    const { title, description, price, downloadUrl, thumbnailUrl } = req.body;

    if (!title || price === undefined || !downloadUrl) {
      return res.status(400).json({ success: false, error: 'Missing required parameters: title, price, or downloadUrl' });
    }

    if (typeof price !== 'number' || price < 0) {
      return res.status(400).json({ success: false, error: 'Price must be a non-negative number' });
    }

    const productRef = db.collection('products').doc();
    const newProduct = {
      title: title,
      description: description || '',
      price: price,
      downloadUrl: downloadUrl,
      thumbnailUrl: thumbnailUrl || '',
      status: 'active',
      totalSales: 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    await productRef.set(newProduct);

    return res.status(201).json({
      success: true,
      message: 'Product created successfully',
      productId: productRef.id,
      product: newProduct
    });
  } catch (error) {
    console.error('Admin Product Creation Error:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// SERVER INITIALIZATION
// --------------------------------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Kit Digital96 Backend Server live on port ${PORT}`);
});
        
