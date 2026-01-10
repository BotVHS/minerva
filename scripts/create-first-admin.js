/**
 * Script per crear el primer usuari administrador.
 *
 * Executa aquest script amb mongosh:
 * mongosh minerva_db create-first-admin.js
 *
 * O des de mongosh:
 * use minerva_db
 * load('create-first-admin.js')
 */

// Connectar a la base de dades minerva_db
db = db.getSiblingDB('minerva_db');

// Dades de l'administrador inicial
const adminData = {
    username: 'admin',
    email: 'admin@minerva.gov',
    fullName: 'System Administrator',
    // Password hash per "Admin123!@#" (canvia-ho després del primer login!)
    // Aquest hash és amb Argon2id - IMPORTANT: Cal canviar la contrasenya immediatament després del primer login
    passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$PLACEHOLDER',  // Es generarà al backend
    roles: ['ADMIN'],
    active: true,
    twoFactorEnabled: false,  // Cal configurar després del primer login
    totpSecret: null,         // Es generarà quan configuri el 2FA
    failedLoginAttempts: 0,
    lockedUntil: null,
    lastLoginAt: null,
    lastLoginIp: null,
    lastPasswordChangeAt: new Date(),
    lastDeviceFingerprint: null,
    createdAt: new Date(),
    updatedAt: new Date()
};

// Comprovar si ja existeix un admin
const existingAdmin = db.User.findOne({ username: 'admin' });
if (existingAdmin) {
    print('❌ ERROR: L\'usuari admin ja existeix!');
    print('Si has oblidat la contrasenya, pots esborrar-lo i tornar a executar aquest script:');
    print('  db.User.deleteOne({ username: "admin" })');
} else {
    // NOTA: Aquest script NO pot generar el hash Argon2id correctament.
    // Has d'usar l'endpoint especial del backend per crear el primer admin.
    print('⚠️  ATENCIÓ: Aquest script és només per referència.');
    print('');
    print('Per crear el primer administrador, usa l\'endpoint especial del backend:');
    print('');
    print('POST http://localhost:8080/api/setup/first-admin');
    print('Content-Type: application/json');
    print('');
    print('Body:');
    print(JSON.stringify({
        username: 'admin',
        password: 'Admin123!@#',
        email: 'admin@minerva.gov',
        fullName: 'System Administrator'
    }, null, 2));
    print('');
    print('Aquest endpoint només funcionarà si no hi ha cap usuari a la base de dades.');
    print('Després de crear l\'admin, l\'endpoint es desactivarà automàticament.');
}
