const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const nodemailer = require('nodemailer');
const multer = require('multer');
const fs = require('fs');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ===== CONFIGURATION =====
const SECRET_KEY = '291025';
const SUPER_ADMIN_USERNAME = 'ntl13k11';
const SUPER_ADMIN_PASSWORD = '300911';
const ADMIN_EMAIL = 'n.marignier.webenter@gmail.com';
const ADMIN_PHONE = '0775794342';

// ===== CONFIGURATION MULTER POUR UPLOADS =====
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
    console.log('✅ Dossier uploads créé');
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const timestamp = Date.now();
        const orderId = req.body.orderId;
        cb(null, `order_${orderId}_${timestamp}.rar`);
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/x-rar-compressed' || file.originalname.endsWith('.rar')) {
            cb(null, true);
        } else {
            cb(new Error('Seules les archives RAR sont acceptées'), false);
        }
    }
});

// ===== CONFIGURATION EMAIL =====
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'n.marignier.webenter@gmail.com',
        pass: 'ftuj yqzm ohmq pssn'
    }
});

transporter.verify((error, success) => {
    if (error) {
        console.log('⚠️ Email non configuré:', error.message);
    } else {
        console.log('✅ Serveur email prêt');
    }
});

// ===== MIDDLEWARE STATIQUE =====
app.use(express.static(path.join(__dirname, '../frontend')));

// ===== MIDDLEWARE BODY PARSER =====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== MIDDLEWARE SESSION =====
app.use(session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24
    }
}));

// ===== BASE DE DONNÉES =====
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'), (err) => {
    if (err) {
        console.error('❌ Erreur connexion DB:', err);
    } else {
        console.log('✅ Base de données connectée');
    }
});

function runAsync(query, params = []) {
    return new Promise((resolve, reject) => {
        db.run(query, params, function(err) {
            if (err) reject(err);
            else resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

function getAsync(query, params = []) {
    return new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function allAsync(query, params = []) {
    return new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
        });
    });
}

// Créer les tables
db.serialize(() => {
    // Table des commandes (inchangée)
    db.run(`
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            clientId INTEGER,
            pack TEXT NOT NULL,
            firstName TEXT NOT NULL,
            lastName TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            businessName TEXT NOT NULL,
            businessType TEXT NOT NULL,
            address TEXT,
            city TEXT,
            postalCode TEXT,
            description TEXT NOT NULL,
            objectives TEXT,
            price REAL NOT NULL,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            confirmed BOOLEAN DEFAULT 0,
            completed BOOLEAN DEFAULT 0,
            delivered BOOLEAN DEFAULT 0,
            deliveredAt DATETIME,
            FOREIGN KEY(clientId) REFERENCES clients(id)
        )
    `, (err) => {
        if (err) console.error('Erreur création table orders:', err);
        else console.log('✅ Table orders prête');
    });

    // Table des clients
    db.run(`
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            passwordHash TEXT NOT NULL,
            businessName TEXT NOT NULL,
            firstName TEXT NOT NULL,
            lastName TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            city TEXT,
            postalCode TEXT,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            lastLogin DATETIME
        )
    `, (err) => {
        if (err) console.error('Erreur création table clients:', err);
        else console.log('✅ Table clients prête');
    });

    // Table des admins
    db.run(`
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            passwordHash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'admin',
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) console.error('Erreur création table admins:', err);
        else console.log('✅ Table admins prête');
    });

    // Table des messages chat
    db.run(`
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            orderId INTEGER NOT NULL,
            senderType TEXT NOT NULL,
            senderId INTEGER,
            message TEXT NOT NULL,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(orderId) REFERENCES orders(id)
        )
    `, (err) => {
        if (err) console.error('Erreur création table chat_messages:', err);
        else console.log('✅ Table chat_messages prête');
    });

    db.run(`
        CREATE TABLE IF NOT EXISTS order_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            orderId INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            uploadedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(orderId) REFERENCES orders(id)
        )
    `, (err) => {
        if (err) console.error('Erreur création table order_files:', err);
        else console.log('✅ Table order_files prête');
    });

    const hashedPassword = bcrypt.hashSync(SUPER_ADMIN_PASSWORD, 10);
    db.run(
        `INSERT OR IGNORE INTO admins (username, passwordHash, email, role) 
         VALUES (?, ?, ?, ?)`,
        [SUPER_ADMIN_USERNAME, hashedPassword, ADMIN_EMAIL, 'superadmin'],
        (err) => {
            if (err) console.error('Erreur création super-admin:', err);
            else console.log(`✅ Super-admin initialisé: ${SUPER_ADMIN_USERNAME}`);
        }
    );
});

// ===== MIDDLEWARES D'AUTHENTIFICATION =====
function requireAuth(req, res, next) {
    if (req.session.adminId) {
        next();
    } else {
        res.status(401).json({ error: 'Non authentifié' });
    }
}

function requireSuperAdmin(req, res, next) {
    if (req.session.adminRole === 'superadmin') {
        next();
    } else {
        res.status(403).json({ error: 'Accès refusé' });
    }
}

function requireClientAuth(req, res, next) {
    if (req.session.clientId) {
        next();
    } else {
        res.status(401).json({ error: 'Non authentifié' });
    }
}

// ===== VALIDATION MOT DE PASSE CLIENT =====
function validatePassword(password) {
    // Min 6 caractères, 1 majuscule, 1 minuscule, 1 chiffre
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;
    return regex.test(password);
}

// ===== FONCTIONS EMAIL =====
async function sendConfirmationEmail(order) {
    const htmlContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #667eea;">✅ Commande Confirmée</h2>
            <p>Bonjour <strong>${order.firstName} ${order.lastName}</strong>,</p>
            <p>Merci de votre confiance ! Votre commande <strong>#${order.id}</strong> a été reçue.</p>
            <div style="background: #f7fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
                <p><strong>Pack:</strong> ${order.pack === 'express' ? 'Express (49€)' : 'Pro (99€)'}</p>
                <p><strong>Entreprise:</strong> ${order.businessName}</p>
            </div>
            <p>Nous vous contacterons très bientôt pour finaliser les détails.</p>
            <p>📞 <strong>Contact:</strong> ${ADMIN_EMAIL} | ${ADMIN_PHONE}</p>
            <p><a href="https://webenter.fr/client/login" style="display: inline-block; background: #667eea; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none;">Voir ma commande</a></p>
            <p style="margin-top: 30px; color: #718096; font-size: 12px;">© 2026 WebEnter</p>
        </div>
    `;

    try {
        await transporter.sendMail({
            from: ADMIN_EMAIL,
            to: order.email,
            subject: `✅ Confirmation de commande #${order.id} - WebEnter`,
            html: htmlContent
        });
        console.log(`✅ Email de confirmation envoyé à ${order.email}`);
    } catch (error) {
        console.error('❌ Erreur email confirmation:', error);
    }
}

async function sendCompletionEmail(order) {
    const htmlContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #48bb78;">🎉 Commande Complétée</h2>
            <p>Bonjour <strong>${order.firstName} ${order.lastName}</strong>,</p>
            <p>Merci ! Votre commande <strong>#${order.id}</strong> a été traitée avec succès.</p>
            <div style="background: #e6f9f0; padding: 20px; border-radius: 10px; margin: 20px 0;">
                <p><strong>Statut:</strong> ✅ Complétée</p>
                <p><strong>Pack:</strong> ${order.pack === 'express' ? 'Express' : 'Pro'}</p>
            </div>
            <p>Veuillez vérifier la section "Mes Commandes" pour plus de détails.</p>
            <p><a href="https://webenter.fr/client/dashboard" style="display: inline-block; background: #48bb78; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none;">Voir ma commande</a></p>
            <p style="margin-top: 30px; color: #718096; font-size: 12px;">© 2026 WebEnter</p>
        </div>
    `;

    try {
        await transporter.sendMail({
            from: ADMIN_EMAIL,
            to: order.email,
            subject: `🎉 Commande #${order.id} complétée - WebEnter`,
            html: htmlContent
        });
        console.log(`✅ Email de complétion envoyé à ${order.email}`);
    } catch (error) {
        console.error('❌ Erreur email complétion:', error);
    }
}

async function sendDeliveryEmail(order) {
    const htmlContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #667eea;">📦 Livraison Effectuée</h2>
            <p>Bonjour <strong>${order.firstName} ${order.lastName}</strong>,</p>
            <p>Votre commande <strong>#${order.id}</strong> a été livrée avec succès !</p>
            <div style="background: #f0f4ff; padding: 20px; border-radius: 10px; margin: 20px 0;">
                <p><strong>📦 Archive disponible</strong></p>
                <p>Vous pouvez télécharger votre archive depuis votre compte.</p>
            </div>
            <p><a href="https://webenter.fr/client/dashboard" style="display: inline-block; background: #667eea; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none;">Accéder à votre compte</a></p>
            <p>Pour toute question, consultez l'onglet "Chat" de votre commande.</p>
            <p style="margin-top: 30px; color: #718096; font-size: 12px;">© 2026 WebEnter</p>
        </div>
    `;

    try {
        await transporter.sendMail({
            from: ADMIN_EMAIL,
            to: order.email,
            subject: `📦 Votre commande #${order.id} a été livrée - WebEnter`,
            html: htmlContent
        });
        console.log(`✅ Email de livraison envoyé à ${order.email}`);
    } catch (error) {
        console.error('❌ Erreur email livraison:', error);
    }
}

async function sendChatNotification(order, adminName) {
    const htmlContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #667eea;">💬 Nouveau Message</h2>
            <p>Bonjour <strong>${order.firstName} ${order.lastName}</strong>,</p>
            <p><strong>${adminName}</strong> vous a envoyé un message sur votre commande <strong>#${order.id}</strong>.</p>
            <p><a href="https://webenter.fr/client/dashboard" style="display: inline-block; background: #667eea; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none;">Voir le message</a></p>
            <p style="margin-top: 30px; color: #718096; font-size: 12px;">© 2026 WebEnter</p>
        </div>
    `;

    try {
        await transporter.sendMail({
            from: ADMIN_EMAIL,
            to: order.email,
            subject: `💬 Nouveau message sur votre commande #${order.id} - WebEnter`,
            html: htmlContent
        });
    } catch (error) {
        console.error('❌ Erreur notification chat:', error);
    }
}

// ===== WEBSOCKET POUR CHAT =====
const chatConnections = new Map();

wss.on('connection', (ws) => {
    let orderId = null;
    let userType = null;
    let userId = null;

    ws.on('message', async (data) => {
        try {
            const msg = JSON.parse(data);
            
            if (msg.type === 'join') {
                orderId = msg.orderId;
                userType = msg.userType;
                userId = msg.userId;
                
                if (!chatConnections.has(orderId)) {
                    chatConnections.set(orderId, []);
                }
                chatConnections.get(orderId).push(ws);
                
                ws.send(JSON.stringify({ type: 'connected', orderId }));
            }
            
            if (msg.type === 'message' && orderId) {
                const messageData = {
                    id: Date.now(),
                    orderId,
                    senderType: userType,
                    senderId: userId,
                    message: msg.content,
                    createdAt: new Date().toISOString()
                };
                
                await runAsync(
                    'INSERT INTO chat_messages (orderId, senderType, senderId, message) VALUES (?, ?, ?, ?)',
                    [orderId, userType, userId, msg.content]
                );
                
                const connections = chatConnections.get(orderId) || [];
                connections.forEach(conn => {
                    if (conn.readyState === WebSocket.OPEN) {
                        conn.send(JSON.stringify({ type: 'message', data: messageData }));
                    }
                });
                
                if (userType === 'admin') {
                    const order = await getAsync('SELECT * FROM orders WHERE id = ?', [orderId]);
                    const admin = await getAsync('SELECT * FROM admins WHERE id = ?', [userId]);
                    if (order && admin) {
                        await sendChatNotification(order, admin.username);
                    }
                }
            }
        } catch (error) {
            console.error('Erreur WebSocket:', error);
        }
    });

    ws.on('close', () => {
        if (orderId && chatConnections.has(orderId)) {
            const connections = chatConnections.get(orderId);
            const index = connections.indexOf(ws);
            if (index > -1) {
                connections.splice(index, 1);
            }
        }
    });
});

// ===== ROUTES AUTHENTIFICATION CLIENTS =====
app.post('/api/client/register', async (req, res) => {
    try {
        const { email, password, businessName, firstName, lastName } = req.body;
        
        if (!email || !password || !businessName || !firstName || !lastName) {
            return res.status(400).json({ error: 'Tous les champs sont obligatoires' });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ 
                error: 'Le mot de passe doit contenir au minimum: 6 caractères, 1 majuscule, 1 minuscule, 1 chiffre' 
            });
        }

        const existing = await getAsync('SELECT id FROM clients WHERE email = ?', [email]);
        if (existing) {
            return res.status(400).json({ error: 'Email déjà enregistré' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const result = await runAsync(
            'INSERT INTO clients (email, passwordHash, businessName, firstName, lastName) VALUES (?, ?, ?, ?, ?)',
            [email, hashedPassword, businessName, firstName, lastName]
        );

        req.session.clientId = result.lastID;
        req.session.clientEmail = email;
        req.session.clientBusinessName = businessName;
        req.session.clientFirstName = firstName;
        req.session.clientLastName = lastName;

        res.json({
            success: true,
            message: 'Compte créé avec succès',
            clientId: result.lastID
        });
    } catch (error) {
        console.error('Erreur inscription client:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/client/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email et mot de passe requis' });
        }

        const client = await getAsync('SELECT * FROM clients WHERE email = ?', [email]);
        if (!client) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        const validPassword = bcrypt.compareSync(password, client.passwordHash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        req.session.clientId = client.id;
        req.session.clientEmail = client.email;
        req.session.clientBusinessName = client.businessName;
        req.session.clientFirstName = client.firstName;
        req.session.clientLastName = client.lastName;

        await runAsync('UPDATE clients SET lastLogin = CURRENT_TIMESTAMP WHERE id = ?', [client.id]);

        res.json({
            success: true,
            message: 'Connecté avec succès',
            clientId: client.id,
            businessName: client.businessName
        });
    } catch (error) {
        console.error('Erreur login client:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/client/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

app.get('/api/client/check', (req, res) => {
    if (req.session.clientId) {
        res.json({
            authenticated: true,
            client: {
                id: req.session.clientId,
                email: req.session.clientEmail,
                firstName: req.session.clientFirstName,
                lastName: req.session.clientLastName
            }
        });
    } else {
        res.json({ authenticated: false });
    }
});

// ===== ROUTES COMMANDES CLIENT =====
app.get('/api/client/orders', requireClientAuth, async (req, res) => {
    try {
        const orders = await allAsync(
            'SELECT * FROM orders WHERE clientId = ? ORDER BY createdAt DESC',
            [req.session.clientId]
        );
        res.json(orders);
    } catch (error) {
        console.error('Erreur récupération commandes:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/client/order/:id', requireClientAuth, async (req, res) => {
    try {
        const order = await getAsync(
            'SELECT * FROM orders WHERE id = ? AND clientId = ?',
            [req.params.id, req.session.clientId]
        );
        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }
        res.json(order);
    } catch (error) {
        console.error('Erreur récupération commande:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/client/order/:id/messages', requireClientAuth, async (req, res) => {
    try {
        const order = await getAsync(
            'SELECT * FROM orders WHERE id = ? AND clientId = ?',
            [req.params.id, req.session.clientId]
        );
        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        const messages = await allAsync(
            'SELECT * FROM chat_messages WHERE orderId = ? ORDER BY createdAt ASC',
            [req.params.id]
        );
        res.json(messages.map(m => ({
            id: m.id,
            orderId: m.orderId,
            type: m.senderType,
            content: m.message,
            createdAt: m.createdAt
        })));
    } catch (error) {
        console.error('Erreur récupération messages:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// POST message client
app.post('/api/client/order/:id/messages', requireClientAuth, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content) {
            return res.status(400).json({ error: 'Message vide' });
        }

        const order = await getAsync(
            'SELECT * FROM orders WHERE id = ? AND clientId = ?',
            [req.params.id, req.session.clientId]
        );
        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        await runAsync(
            'INSERT INTO chat_messages (orderId, senderType, senderId, message) VALUES (?, ?, ?, ?)',
            [req.params.id, 'client', req.session.clientId, content]
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Erreur envoi message:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// GET fichiers livrés
app.get('/api/client/order/:id/files', requireClientAuth, async (req, res) => {
    try {
        const order = await getAsync(
            'SELECT * FROM orders WHERE id = ? AND clientId = ?',
            [req.params.id, req.session.clientId]
        );
        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        const files = await allAsync(
            'SELECT * FROM order_files WHERE orderId = ? ORDER BY uploadedAt DESC',
            [req.params.id]
        );
        res.json(files || []);
    } catch (error) {
        console.error('Erreur fichiers:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// GET commandes pour le dashboard du client (pas /api/client/orders en double)
app.get('/api/client/orders', requireClientAuth, async (req, res) => {
    try {
        const orders = await allAsync(
            'SELECT * FROM orders WHERE clientId = ? ORDER BY createdAt DESC',
            [req.session.clientId]
        );
        res.json(orders);
    } catch (error) {
        console.error('Erreur récupération commandes:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ===== ROUTES AUTHENTIFICATION ADMIN (inchangées) =====
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Identifiants manquants' });
        }

        const admin = await getAsync('SELECT * FROM admins WHERE username = ?', [username]);
        if (!admin) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }

        const validPassword = bcrypt.compareSync(password, admin.passwordHash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }

        req.session.adminId = admin.id;
        req.session.adminUsername = admin.username;
        req.session.adminRole = admin.role;

        res.json({
            success: true,
            message: 'Connecté avec succès',
            role: admin.role
        });
    } catch (error) {
        console.error('Erreur login:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

app.get('/api/auth/check', (req, res) => {
    if (req.session.adminId) {
        res.json({
            authenticated: true,
            username: req.session.adminUsername,
            role: req.session.adminRole
        });
    } else {
        res.json({ authenticated: false });
    }
});

// ===== ROUTES COMMANDES (inchangées) =====
app.get('/api/orders', requireAuth, async (req, res) => {
    try {
        const orders = await allAsync('SELECT * FROM orders ORDER BY createdAt DESC');
        res.json(orders);
    } catch (error) {
        console.error('Erreur récupération commandes:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/orders', async (req, res) => {
    try {
        const { 
            pack, firstName, lastName, email, phone, 
            businessName, businessType, address, city, postalCode,
            description, objectives, price
        } = req.body;

        // Validation des champs obligatoires
        if (!pack || !firstName || !lastName || !email || !businessName || !businessType || !description) {
            return res.status(400).json({ error: 'Champs obligatoires manquants' });
        }

        const clientId = req.session.clientId || null;

        const result = await runAsync(
            `INSERT INTO orders 
            (clientId, pack, firstName, lastName, email, phone, businessName, businessType, address, city, postalCode, description, objectives, price) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                clientId, 
                pack, 
                firstName, 
                lastName, 
                email, 
                phone?.trim() || null, 
                businessName, 
                businessType, 
                address?.trim() || null, 
                city?.trim() || null, 
                postalCode?.trim() || null, 
                description, 
                objectives?.trim() || null,  // Convertir string vide en null
                price || 0
            ]
        );

        const order = await getAsync('SELECT * FROM orders WHERE id = ?', [result.lastID]);
        
        // Envoyer l'email mais ne pas bloquer si ça échoue
        try {
            await sendConfirmationEmail(order);
        } catch (emailError) {
            console.error('Erreur email (non bloquante):', emailError);
        }

        res.json({
            success: true,
            message: 'Commande créée avec succès',
            orderId: result.lastID
        });
    } catch (error) {
        console.error('Erreur création commande:', error);
        res.status(500).json({ error: 'Erreur serveur: ' + error.message });
    }
});

app.get('/api/orders/filter', requireAuth, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        if (!startDate || !endDate) {
            return res.status(400).json({ error: 'Dates manquantes' });
        }

        const orders = await allAsync(
            `SELECT * FROM orders 
             WHERE DATE(createdAt) BETWEEN ? AND ?
             ORDER BY createdAt DESC`,
            [startDate, endDate]
        );

        res.json(orders);
    } catch (error) {
        console.error('Erreur filtre:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/orders/:id/confirm', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const order = await getAsync('SELECT * FROM orders WHERE id = ?', [id]);
        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        await runAsync('UPDATE orders SET confirmed = 1 WHERE id = ?', [id]);
        await sendConfirmationEmail(order);

        res.json({ success: true, message: 'Confirmation envoyée au client' });
    } catch (error) {
        console.error('Erreur confirmation:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/orders/:id/complete', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const order = await getAsync('SELECT * FROM orders WHERE id = ?', [id]);
        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        await runAsync('UPDATE orders SET completed = 1, status = ? WHERE id = ?', 
            ['completed', id]);

        await sendCompletionEmail(order);

        res.json({ success: true, message: 'Commande complétée et email envoyé' });
    } catch (error) {
        console.error('Erreur completion:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// GET messages pour admin
app.get('/api/orders/:id/messages', requireAuth, async (req, res) => {
    try {
        const messages = await allAsync(
            'SELECT * FROM chat_messages WHERE orderId = ? ORDER BY createdAt ASC',
            [req.params.id]
        );
        res.json(messages.map(m => ({
            id: m.id,
            orderId: m.orderId,
            type: m.senderType,
            content: m.message,
            createdAt: m.createdAt
        })));
    } catch (error) {
        console.error('Erreur messages:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/orders/deliver', requireAuth, upload.single('file'), async (req, res) => {
    try {
        const { orderId } = req.body;
        
        if (!orderId) {
            return res.status(400).json({ error: 'ID commande manquant' });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'Aucun fichier uploadé' });
        }

        const order = await getAsync('SELECT * FROM orders WHERE id = ?', [orderId]);
        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        // Sauvegarder le fichier dans la BD
        await runAsync(
            'INSERT INTO order_files (orderId, filename, filepath) VALUES (?, ?, ?)',
            [orderId, req.file.filename, req.file.path]
        );

        await runAsync('UPDATE orders SET delivered = 1, deliveredAt = CURRENT_TIMESTAMP WHERE id = ?', [orderId]);
        await sendDeliveryEmail(order);

        console.log(`✅ Archive livrée pour la commande #${orderId}`);
        console.log(`📁 Fichier sauvegardé: ${req.file.filename}`);

        res.json({
            success: true,
            message: 'Archive livrée avec succès',
            fileName: req.file.filename
        });

    } catch (error) {
        console.error('❌ Erreur livraison:', error);
        res.status(500).json({ error: 'Erreur lors de la livraison: ' + error.message });
    }
});

app.post('/api/orders/:id/message', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { message } = req.body;
        
        if (!message) {
            return res.status(400).json({ error: 'Message vide' });
        }

        const order = await getAsync('SELECT * FROM orders WHERE id = ?', [id]);
        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        await runAsync(
            'INSERT INTO chat_messages (orderId, senderType, senderId, message) VALUES (?, ?, ?, ?)',
            [id, 'admin', req.session.adminId, message]
        );

        await sendChatNotification(order, req.session.adminUsername);

        res.json({ success: true });
    } catch (error) {
        console.error('Erreur envoi message:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/stats', requireAuth, async (req, res) => {
    try {
        const stats = await getAsync(
            `SELECT 
                COUNT(*) as totalOrders,
                COUNT(CASE WHEN status='completed' THEN 1 END) as completedOrders,
                SUM(CASE WHEN status='completed' THEN price ELSE 0 END) as totalRevenue
             FROM orders`
        );

        res.json({
            totalOrders: stats.totalOrders || 0,
            completedOrders: stats.completedOrders || 0,
            totalRevenue: stats.totalRevenue || 0
        });
    } catch (error) {
        console.error('Erreur stats:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ===== ROUTES GESTION DES ADMINS =====
app.post('/api/admins', requireSuperAdmin, async (req, res) => {
    try {
        const { username, password, email } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Identifiants manquants' });
        }

        if (!/^\d{6}$/.test(password)) {
            return res.status(400).json({ error: 'Le mot de passe doit être exactement 6 chiffres' });
        }

        if (username.length < 3) {
            return res.status(400).json({ error: 'Username trop court (min 3 caractères)' });
        }

        const existing = await getAsync('SELECT id FROM admins WHERE username = ?', [username]);
        if (existing) {
            return res.status(400).json({ error: 'Username déjà existant' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const result = await runAsync(
            'INSERT INTO admins (username, passwordHash, email, role) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, email || null, 'admin']
        );

        res.json({
            success: true,
            message: 'Admin créé avec succès',
            adminId: result.lastID
        });
    } catch (error) {
        console.error('Erreur création admin:', error);
        res.status(500).json({ error: 'Erreur serveur: ' + error.message });
    }
});

app.get('/api/admins', requireSuperAdmin, async (req, res) => {
    try {
        const admins = await allAsync(
            'SELECT id, username, email, role, createdAt FROM admins ORDER BY createdAt DESC'
        );
        res.json(admins);
    } catch (error) {
        console.error('Erreur récupération admins:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.delete('/api/admins/:id', requireSuperAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const user = await getAsync('SELECT role FROM admins WHERE id = ?', [id]);
        
        if (!user) {
            return res.status(404).json({ error: 'Admin non trouvé' });
        }

        if (user.role === 'superadmin') {
            return res.status(403).json({ error: 'Impossible de supprimer le super-admin' });
        }

        await runAsync('DELETE FROM admins WHERE id = ?', [id]);
        res.json({ success: true, message: 'Admin supprimé' });
    } catch (error) {
        console.error('Erreur suppression admin:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ===== ROUTES PAGES ADMIN =====
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/admin/login.html'));
});

app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/admin/dashboard.html'));
});

app.get('/admin/manage-admins', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/admin/manage-admins-improved.html'));
});

app.get('/admin/delivery', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/admin/delivery.html'));
});

// ===== ROUTES PAGES CLIENT =====
app.get('/client/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/client/login.html'));
});

app.get('/client/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/client/register.html'));
});

app.get('/client/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/client/dashboard.html'));
});

app.get('/client/order', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/client/order.html'));
});

// ===== ROUTES API CLIENT =====
app.get('/api/client/check', (req, res) => {
    if (req.session.clientId) {
        res.json({
            authenticated: true,
            client: {
                id: req.session.clientId,
                email: req.session.clientEmail,
                firstName: req.session.clientFirstName,
                lastName: req.session.clientLastName
            }
        });
    } else {
        res.json({ authenticated: false });
    }
});

app.get('/api/client/orders', requireClientAuth, async (req, res) => {
    try {
        const orders = await allAsync(
            'SELECT * FROM orders WHERE clientId = ? ORDER BY createdAt DESC',
            [req.session.clientId]
        );
        res.json(orders);
    } catch (error) {
        console.error('Erreur récupération commandes:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/client/orders/:id/message', requireClientAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { message } = req.body;

        if (!message) {
            return res.status(400).json({ error: 'Message vide' });
        }

        const order = await getAsync('SELECT * FROM orders WHERE id = ? AND clientId = ?', [id, req.session.clientId]);
        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        await runAsync(
            'INSERT INTO chat_messages (orderId, senderType, senderId, message) VALUES (?, ?, ?, ?)',
            [id, 'client', req.session.clientId, message]
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Erreur envoi message:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/orders/:id/messages', async (req, res) => {
    try {
        const { id } = req.params;
        const messages = await allAsync(
            'SELECT * FROM chat_messages WHERE orderId = ? ORDER BY createdAt ASC',
            [id]
        );
        res.json(messages);
    } catch (error) {
        console.error('Erreur messages:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/orders/:id/download', async (req, res) => {
    try {
        const { id } = req.params;
        const order = await getAsync('SELECT * FROM orders WHERE id = ? AND delivered = 1', [id]);
        
        if (!order) {
            return res.status(404).json({ error: 'Fichiers non disponibles' });
        }

        // Chercher le fichier dans le dossier uploads
        const files = fs.readdirSync(uploadDir);
        const orderFile = files.find(f => f.startsWith(`order_${id}_`));

        if (!orderFile) {
            return res.status(404).json({ error: 'Fichier non trouvé' });
        }

        const filePath = path.join(uploadDir, orderFile);
        res.download(filePath);
    } catch (error) {
        console.error('Erreur téléchargement:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/client/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});


// ===== PAGE ACCUEIL =====
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/index.html'));
});

// ===== PAGES COMMANDE =====
app.get('/order-choice.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/order-choice.html'));
});

app.get('/order.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/order.html'));
});

app.get('/order-visitor.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/order.html'));
});

// ===== GESTION 404 =====
app.use((req, res) => {
    res.status(404).json({ error: 'Page non trouvée' });
});

// ===== GESTION ERREURS =====
app.use((err, req, res, next) => {
    console.error('Erreur serveur:', err);
    res.status(500).json({ error: 'Erreur serveur interne' });
});


// ===== DÉMARRAGE =====
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log('');
    console.log('┌─────────────────────────────────────────────────────┐');
    console.log('│   🚀 WebEnter Serveur Démarré        │');
    console.log('├─────────────────────────────────────────────────────┤');
    console.log(`│ 🌐 URL: http://localhost:${PORT}${' '.repeat(25-PORT.toString().length)}│`);
    console.log('│ 🔤 Super-Admin:                       │');
    console.log(`│    Username: ${SUPER_ADMIN_USERNAME}${' '.repeat(26)}│`);
    console.log(`│    Password: ${SUPER_ADMIN_PASSWORD}${' '.repeat(27)}│`);
    console.log('│ 📦 Panel Livraison: /admin/delivery   │');
    console.log('│ 👥 Gestion Admins: /admin/manage-admins│');
    console.log('│ 📊 Dashboard Admin: /admin/dashboard   │');
    console.log('│ 💼 Dashboard Client: /client/dashboard │');
    console.log('└─────────────────────────────────────────────────────┘');
    console.log('');
});

module.exports = app;
