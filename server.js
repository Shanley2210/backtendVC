require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const { AccessToken } = require('livekit-server-sdk');

const app = express();
app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    next();
});

const serviceAccount = JSON.parse(process.env.GOOGLE_CREDENTIALS);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const LIVEKIT_API_KEY = process.env.LIVEKIT_API_KEY;
const LIVEKIT_SECRET = process.env.LIVEKIT_SECRET;

app.post('/auth', async (req, res) => {
    const { token } = req.body;
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        console.log('🔹 Decoded Firebase Token:', decoded);

        const userName =
            decoded.name ||
            decoded.displayName ||
            (decoded.email ? decoded.email.split('@')[0] : 'Unknown');

        const user = {
            uid: decoded.uid,
            name: userName,
            email: decoded.email
        };

        console.log('✅ Authenticated User:', user);

        const accessToken = jwt.sign(user, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });

        res.json({ accessToken, user });
    } catch (error) {
        console.error('❌ Authentication Error:', error);
        res.status(401).json({ error: 'Unauthorized' });
    }
});

app.post('/join-room', async (req, res) => {
    const { room, name } = req.body;

    if (!LIVEKIT_API_KEY || !LIVEKIT_SECRET) {
        console.error('❌ Missing LiveKit API key or secret');
        return res.status(500).json({ error: 'LiveKit credentials missing' });
    }

    try {
        const token = new AccessToken(LIVEKIT_API_KEY, LIVEKIT_SECRET, {
            identity: name
        });
        token.addGrant({
            roomJoin: true,
            room: room || 'default-room',
            canPublish: true,
            canSubscribe: true
        });

        const jwtToken = await token.toJwt();

        res.json({ token: jwtToken });
    } catch (error) {
        console.error('❌ LiveKit Token Error:', error);
        res.status(500).json({ error: 'Failed to create LiveKit token' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
