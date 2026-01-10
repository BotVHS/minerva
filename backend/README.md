# Minerva Backend - Quarkus

Backend del sistema de seguretat Minerva implementat amb Quarkus i Java 17.

## 📁 Estructura del Codi

```
backend/src/main/java/cat/minerva/
├── model/                          # Models de dades MongoDB
│   ├── User.java                   # Model d'usuari
│   ├── UserRole.java               # Enum de rols RBAC
│   ├── RefreshToken.java           # Model de refresh tokens
│   ├── AuditLog.java               # Model de logs immutables
│   └── AuditAction.java            # Enum d'accions auditables
│
├── repository/                     # Repositoris MongoDB (Panache)
│   ├── UserRepository.java         # Queries d'usuaris
│   ├── RefreshTokenRepository.java # Queries de tokens
│   └── AuditLogRepository.java     # Queries de logs
│
├── service/                        # Serveis de negoci
│   ├── AuthService.java            # Autenticació 2-fases
│   └── UserService.java            # Gestió d'usuaris
│
├── security/                       # Components de seguretat
│   ├── PasswordHashService.java    # Argon2id hashing
│   ├── TotpService.java            # 2FA amb TOTP (RFC 6238)
│   └── TokenService.java           # JWT + Refresh tokens
│
├── audit/                          # Sistema d'auditoria
│   └── AuditService.java           # Logs immutables tipus blockchain
│
├── resource/                       # Endpoints REST
│   ├── AuthResource.java           # /api/auth/*
│   ├── UserResource.java           # /api/users/*
│   └── AuditResource.java          # /api/audit/*
│
└── dto/                            # Data Transfer Objects
    ├── request/                    # DTOs de peticions
    │   ├── LoginRequest.java
    │   ├── Verify2FARequest.java
    │   ├── RefreshTokenRequest.java
    │   └── CreateUserRequest.java
    └── response/                   # DTOs de respostes
        ├── AuthResponse.java
        └── UserDTO.java
```

## 🔌 API Endpoints

### Autenticació

#### POST /api/auth/login
Login amb credencials (Fase 1)

**Request:**
```json
{
  "username": "john.doe",
  "password": "MyPass123!@#"
}
```

**Response:**
```json
{
  "pending2FA": true,
  "sessionToken": "eyJhbGci...",
  "userId": "507f1f77bcf86cd799439011",
  "message": "Introdueix el codi 2FA"
}
```

#### POST /api/auth/verify-2fa
Validar 2FA (Fase 2)

**Request:**
```json
{
  "userId": "507f1f77bcf86cd799439011",
  "totpCode": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "accessToken": "eyJhbGci...",
  "refreshToken": "7a8b9c0d...",
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "username": "john.doe",
    "roles": ["ANALISTA"],
    "email": "john@example.com"
  }
}
```

#### POST /api/auth/refresh
Renovar tokens

**Request:**
```json
{
  "refreshToken": "7a8b9c0d..."
}
```

**Response:**
```json
{
  "success": true,
  "accessToken": "eyJhbGci...",  // NOU
  "refreshToken": "9i8h7g6f..."   // NOU (rotació)
}
```

#### POST /api/auth/logout
Logout (revocar refresh token)

**Headers:** `Authorization: Bearer [accessToken]`

**Request:**
```json
{
  "refreshToken": "7a8b9c0d..."
}
```

### Gestió d'Usuaris (només ADMIN)

#### POST /api/users
Crear usuari

**Headers:** `Authorization: Bearer [adminToken]`

**Request:**
```json
{
  "username": "maria.garcia",
  "email": "maria@example.com",
  "fullName": "Maria Garcia López",
  "roles": ["ANALISTA"]
}
```

**Response:**
```json
{
  "success": true,
  "user": {...},
  "temporaryPassword": "Xy9$mK2#pL5@qW8!",
  "message": "Usuari creat. Contrasenya temporal: Xy9$mK2#pL5@qW8!"
}
```

#### GET /api/users
Llistar usuaris (ADMIN, SUPERVISOR)

**Headers:** `Authorization: Bearer [token]`

**Response:**
```json
[
  {
    "id": "507f1f77bcf86cd799439011",
    "username": "john.doe",
    "roles": ["ANALISTA"],
    "active": true,
    "twoFactorEnabled": true
  }
]
```

#### GET /api/users/{id}
Obtenir usuari per ID

#### POST /api/users/{id}/roles
Assignar rol

**Request:**
```json
{
  "role": "SUPERVISOR"
}
```

#### DELETE /api/users/{id}/roles/{role}
Eliminar rol

#### POST /api/users/{id}/enable
Activar usuari

#### POST /api/users/{id}/disable
Desactivar usuari

#### POST /api/users/{id}/unlock
Desbloquejar compte

#### POST /api/users/{id}/reset-2fa
Reset 2FA

**Response:**
```json
{
  "success": true,
  "qrCode": "data:image/png;base64,...",
  "message": "2FA reset. L'usuari ha d'escanejar el nou QR code"
}
```

### Logs d'Auditoria (ADMIN, SUPERVISOR)

#### GET /api/audit/logs
Tots els logs

Query params:
- `from`: timestamp inicial (ISO 8601)
- `to`: timestamp final (ISO 8601)
- `limit`: màxim resultats (default: 100)

#### GET /api/audit/logs/user/{userId}
Logs d'un usuari

#### GET /api/audit/logs/failed-logins
Intents de login fallits

#### GET /api/audit/logs/suspicious
Activitat sospitosa

#### GET /api/audit/logs/admin-actions
Accions d'administració (només ADMIN)

#### POST /api/audit/verify-integrity
Verificar integritat de logs (només ADMIN)

**Response:**
```json
{
  "valid": true,
  "totalLogs": 12345,
  "message": "La cadena de logs és íntegra"
}
```

## 🔒 Seguretat

### Autenticació

Totes les peticions (excepte login) requereixen:
```
Authorization: Bearer [accessToken]
```

### Autorització RBAC

Rols implementats:
- **ADMIN**: Accés total, gestió d'usuaris
- **SUPERVISOR**: Supervisió, veure logs
- **ANALISTA**: Accés a dades, anàlisi
- **CONTRIBUIDOR**: Accés bàsic

### Proteccions

- ✅ Validació d'entrada (Bean Validation)
- ✅ CORS configurat
- ✅ Headers de seguretat
- ✅ Rate limiting
- ✅ Bloqueig de compte
- ✅ Tokens vinculats a dispositiu

## 🛠️ Desenvolupament

### Executar en Mode Dev

```bash
cd backend
./mvnw quarkus:dev
```

Accés a:
- API: http://localhost:8080
- Dev UI: http://localhost:8080/q/dev
- Health: http://localhost:8080/health

### Compilar

```bash
./mvnw clean package
```

### Tests

```bash
./mvnw test
```

## 📦 Dependències Principals

| Dependència | Ús |
|-------------|-----|
| quarkus-mongodb-panache | MongoDB + Panache ORM |
| quarkus-smallrye-jwt | JWT authentication |
| argon2-jvm | Hashing de contrasenyes |
| otp-java | TOTP per 2FA |
| zxing | QR codes per 2FA |
| resilience4j | Rate limiting |
| quarkus-hibernate-validator | Validació d'entrada |

## 🔐 Configuració

Veure `application.properties` per configuració completa.

Variables d'entorn clau:
- `MONGODB_USER`: Usuari MongoDB
- `MONGODB_PASSWORD`: Contrasenya MongoDB
- `JWT_ISSUER`: Issuer dels JWT tokens

## 📚 Documentació Relacionada

- [SECURITY.md](../SECURITY.md) - Documentació de seguretat
- [USAGE_EXAMPLES.md](../USAGE_EXAMPLES.md) - Exemples d'ús
- [DEPLOYMENT.md](../DEPLOYMENT.md) - Guia de desplegament
