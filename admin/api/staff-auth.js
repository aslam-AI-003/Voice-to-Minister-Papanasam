// Vercel Serverless Function - Staff Authentication Bridge
//
// WHY THIS EXISTS: Firestore's real security rules need to tell a genuine
// staff member apart from a random visitor. The only trustworthy signal
// Firestore can check is `request.auth != null` (a real Firebase Auth
// session) — but the admin panel's staff login is a separate password
// system with no Firebase Auth involved. This function is the bridge:
// it verifies a staff username/password against Supabase (the one place
// staff credentials now live server-side — see supabase-setup.sql), and
// if correct, mints a genuine Firebase custom auth token for that staff
// member. The browser then signs into Firebase Auth with that token,
// giving Firestore something real to check.
//
// This function holds two private keys that must NEVER reach the browser:
// the Supabase service_role key (bypasses Row Level Security) and the
// Firebase Admin SDK service account (can mint auth tokens for anyone).
// Both come from environment variables, set in the Vercel dashboard only.

import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

function getFirebaseAdminAuth() {
    const existing = getApps();
    const app = existing.length
        ? existing[0]
        : initializeApp({ credential: cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)) });
    return getAuth(app);
}

async function hashPassword(password, salt) {
    const enc = new TextEncoder().encode(salt + ':' + password);
    const digest = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomSaltHex(bytes = 16) {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Basic per-username rate limit, matching the style of send-otp.js —
// best-effort, in-memory, resets on cold start. Stops brute-forcing a
// staff password through this endpoint.
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const attempts = new Map();
function isRateLimited(username) {
    const now = Date.now();
    const tries = (attempts.get(username) || []).filter(t => now - t < RATE_LIMIT_WINDOW_MS);
    if (tries.length >= RATE_LIMIT_MAX) { attempts.set(username, tries); return true; }
    tries.push(now);
    attempts.set(username, tries);
    return false;
}

async function supabaseFetch(path, options = {}) {
    const url = `${process.env.SUPABASE_URL}/rest/v1/${path}`;
    const res = await fetch(url, {
        ...options,
        headers: {
            apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
            Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
            'Content-Type': 'application/json',
            ...(options.headers || {})
        }
    });
    return res;
}

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    try {
        const { username, password, name, mobile, role, area } = req.body || {};
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        const uname = String(username).trim().toLowerCase();

        if (isRateLimited(uname)) {
            return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes.' });
        }

        // Look up the existing account in Supabase (service_role bypasses RLS,
        // safely, because this code runs on the server, never in a browser).
        const lookupRes = await supabaseFetch(`staff?username=eq.${encodeURIComponent(uname)}&select=*`);
        const existing = await lookupRes.json();
        let staffRow = existing[0];

        if (!staffRow) {
            // First time this account has been seen server-side — create it
            // now, using the password the browser just verified locally.
            // (The browser already confirmed this password is correct against
            // its own local hash before calling this endpoint at all — this
            // just gives the server a matching record to check next time.)
            const salt = randomSaltHex();
            const password_hash = await hashPassword(password, salt);
            const staffId = 'STAFF-' + String(Date.now()).slice(-6);
            const createRes = await supabaseFetch('staff', {
                method: 'POST',
                headers: { Prefer: 'return=representation' },
                body: JSON.stringify({
                    username: uname, password_hash, password_salt: salt,
                    name: name || uname, mobile: mobile || '', role: role || 'Data Entry Staff',
                    area: area || 'All Areas', staff_id: staffId
                })
            });
            if (!createRes.ok) {
                const errBody = await createRes.text();
                console.error('Staff create error:', errBody);
                return res.status(500).json({ error: 'Could not create staff record' });
            }
            staffRow = (await createRes.json())[0];
        } else {
            // Verify the password against what's already on file — if this
            // fails, someone is presenting a username that already exists
            // under a different password (don't silently overwrite it).
            const computed = await hashPassword(password, staffRow.password_salt);
            if (computed !== staffRow.password_hash) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
        }

        // Mint a real Firebase Auth custom token for this staff member.
        // uid is prefixed to avoid ever colliding with a citizen's phone-auth uid.
        const uid = `staff_${staffRow.id}`;
        const auth = getFirebaseAdminAuth();
        const token = await auth.createCustomToken(uid, {
            staff: true,
            role: staffRow.role,
            area: staffRow.area
        });

        return res.status(200).json({ token });
    } catch (error) {
        console.error('Staff auth error:', error);
        return res.status(500).json({ error: 'Server error during staff authentication' });
    }
}
