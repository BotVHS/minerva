// MongoDB Setup Script per Minerva Security System
//
// Aquest script configura MongoDB amb:
// - Base de dades i usuaris
// - Índexs per rendiment
// - Validació de documents
// - Col·leccions amb configuració de seguretat
//
// Executar amb: mongosh < mongodb-setup.js

// Connexió a la base de dades
use minerva_db;

print("=== Minerva MongoDB Setup ===");
print("Creating database and collections...");

// Crear col·leccions
db.createCollection("users");
db.createCollection("refresh_tokens");
db.createCollection("audit_logs");

print("Collections created successfully");

// ÍNDEXS PER USERS
print("\nCreating indexes for users collection...");

// Índex únic per username (cerca ràpida i unicitat)
db.users.createIndex(
    { username: 1 },
    { unique: true, name: "idx_username" }
);

// Índex per email (opcional però útil per cerca)
db.users.createIndex(
    { email: 1 },
    { sparse: true, name: "idx_email" }
);

// Índex per rols (cerca d'usuaris per rol)
db.users.createIndex(
    { roles: 1 },
    { name: "idx_roles" }
);

// Índex per compte actiu (cerca d'usuaris actius)
db.users.createIndex(
    { active: 1 },
    { name: "idx_active" }
);

// Índex per últim login (troba usuaris inactius)
db.users.createIndex(
    { lastLoginAt: 1 },
    { name: "idx_last_login" }
);

// Índex per comptes bloquejats
db.users.createIndex(
    { lockedUntil: 1 },
    { sparse: true, name: "idx_locked_until" }
);

print("User indexes created");

// ÍNDEXS PER REFRESH_TOKENS
print("\nCreating indexes for refresh_tokens collection...");

// Índex únic per tokenHash (cerca ràpida)
db.refresh_tokens.createIndex(
    { tokenHash: 1 },
    { unique: true, name: "idx_token_hash" }
);

// Índex per userId (troba tots els tokens d'un usuari)
db.refresh_tokens.createIndex(
    { userId: 1 },
    { name: "idx_user_id" }
);

// Índex compost per userId + deviceFingerprint
db.refresh_tokens.createIndex(
    { userId: 1, deviceFingerprint: 1 },
    { name: "idx_user_device" }
);

// Índex per data d'expiració (neteja de tokens expirats)
db.refresh_tokens.createIndex(
    { expiresAt: 1 },
    { name: "idx_expires_at" }
);

// Índex per tokens revocats
db.refresh_tokens.createIndex(
    { revoked: 1 },
    { name: "idx_revoked" }
);

// TTL Index: elimina automàticament tokens expirats després de 7 dies
db.refresh_tokens.createIndex(
    { expiresAt: 1 },
    { expireAfterSeconds: 604800, name: "idx_ttl_cleanup" } // 7 dies
);

print("Refresh token indexes created");

// ÍNDEXS PER AUDIT_LOGS
print("\nCreating indexes for audit_logs collection...");

// Índex per sequenceNumber (ordre de la cadena)
db.audit_logs.createIndex(
    { sequenceNumber: 1 },
    { unique: true, name: "idx_sequence" }
);

// Índex per userId (cerca logs d'un usuari)
db.audit_logs.createIndex(
    { userId: 1, timestamp: -1 },
    { name: "idx_user_timestamp" }
);

// Índex per timestamp (cerca per dates)
db.audit_logs.createIndex(
    { timestamp: -1 },
    { name: "idx_timestamp" }
);

// Índex per acció (cerca per tipus d'acció)
db.audit_logs.createIndex(
    { action: 1, timestamp: -1 },
    { name: "idx_action_timestamp" }
);

// Índex per IP (detectar activitat des d'una IP)
db.audit_logs.createIndex(
    { ipAddress: 1, timestamp: -1 },
    { name: "idx_ip_timestamp" }
);

// Índex per success (troba només fallides)
db.audit_logs.createIndex(
    { success: 1, action: 1, timestamp: -1 },
    { name: "idx_success_action_timestamp" }
);

// Índex per verificació
db.audit_logs.createIndex(
    { verified: 1 },
    { name: "idx_verified" }
);

print("Audit log indexes created");

// VALIDACIÓ DE DOCUMENTS
print("\nSetting up document validation...");

// Validació per users
db.runCommand({
    collMod: "users",
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["username", "passwordHash", "roles", "active", "createdAt"],
            properties: {
                username: {
                    bsonType: "string",
                    description: "Username is required and must be a string"
                },
                passwordHash: {
                    bsonType: "string",
                    description: "Password hash is required"
                },
                roles: {
                    bsonType: "array",
                    description: "Roles array is required"
                },
                active: {
                    bsonType: "bool",
                    description: "Active status is required"
                },
                email: {
                    bsonType: "string",
                    pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
                    description: "Email must be valid if provided"
                },
                twoFactorEnabled: {
                    bsonType: "bool"
                }
            }
        }
    },
    validationLevel: "moderate",
    validationAction: "error"
});

print("Document validation configured");

// CREAR USUARI ADMIN INICIAL
print("\nCreating initial admin user...");
print("NOTE: This is a default admin. Change the password immediately!");
print("Username: admin");
print("Password: ChangeMe123!@#");
print("");
print("To hash the password with Argon2id, use the application endpoints.");
print("This is just a placeholder for demonstration.");

// ESTADÍSTIQUES
print("\n=== Setup Complete ===");
print("\nCollections:");
print("- users: " + db.users.countDocuments());
print("- refresh_tokens: " + db.refresh_tokens.countDocuments());
print("- audit_logs: " + db.audit_logs.countDocuments());

print("\nIndexes per collection:");
print("- users: " + db.users.getIndexes().length);
print("- refresh_tokens: " + db.refresh_tokens.getIndexes().length);
print("- audit_logs: " + db.audit_logs.getIndexes().length);

print("\n=== IMPORTANT SECURITY NOTES ===");
print("1. Enable MongoDB authentication in production");
print("2. Use TLS/SSL for connections");
print("3. Configure firewall to restrict access");
print("4. Regular backups of audit_logs (immutable data)");
print("5. Monitor failed login attempts");
print("6. Implement database-level encryption at rest");
print("");
print("Setup complete! Please secure your MongoDB instance.");
