# Minerva - Exemples d'Ús

Aquest document mostra exemples pràctics d'ús del sistema Minerva.

## Índex

1. [Setup Inicial](#setup-inicial)
2. [Flux Complet de Login](#flux-complet-de-login)
3. [Creació d'Usuaris](#creació-dusuaris)
4. [Gestió de Rols](#gestió-de-rols)
5. [Consulta de Logs](#consulta-de-logs)
6. [Verificació d'Integritat](#verificació-dintegritat)

---

## Setup Inicial

### 1. Desplegar MongoDB

```bash
# Amb Docker
docker run -d \
  --name minerva-mongo \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=securepass \
  mongo:latest

# Executar script de setup
docker exec -i minerva-mongo mongosh < mongodb-setup.js
```

### 2. Generar Claus JWT

```bash
mkdir -p backend/src/main/resources/keys

# Generar clau privada
openssl genrsa -out backend/src/main/resources/keys/private-key.pem 2048

# Generar clau pública
openssl rsa \
  -in backend/src/main/resources/keys/private-key.pem \
  -pubout \
  -out backend/src/main/resources/keys/public-key.pem
```

### 3. Executar l'Aplicació

```bash
cd backend
./mvnw quarkus:dev
```

L'aplicació estarà disponible a `http://localhost:8080`

---

## Flux Complet de Login

### Pas 1: Login amb Credencials

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "password": "MySecurePass123!@#"
  }'
```

**Resposta**:
```json
{
  "pending2FA": true,
  "sessionToken": "eyJhbGciOiJSUzI1NiIs...",
  "userId": "507f1f77bcf86cd799439011",
  "message": "Introdueix el codi 2FA"
}
```

### Pas 2: Validar 2FA

```bash
curl -X POST http://localhost:8080/api/auth/verify-2fa \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -d '{
    "userId": "507f1f77bcf86cd799439011",
    "totpCode": "123456"
  }'
```

**Resposta**:
```json
{
  "success": true,
  "accessToken": "eyJhbGciOiJSUzI1NiIs...",
  "refreshToken": "7a8b9c0d1e2f3g4h...",
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "username": "john.doe",
    "roles": ["ANALISTA"],
    "email": "john.doe@minerva.gov"
  }
}
```

### Pas 3: Utilitzar Access Token

```bash
curl -X GET http://localhost:8080/api/protected-resource \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

### Pas 4: Renovar Tokens (quan expira)

```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "7a8b9c0d1e2f3g4h..."
  }'
```

**Resposta**:
```json
{
  "success": true,
  "accessToken": "eyJhbGciOiJSUzI1NiIs...",  // NOU
  "refreshToken": "9i8h7g6f5e4d3c2b..."      // NOU (rotació)
}
```

**Important**: El refresh token antic ja no és vàlid!

---

## Creació d'Usuaris

### Només Administradors

```bash
# 1. Login com a admin (seguir flux anterior)

# 2. Crear usuari
curl -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "maria.garcia",
    "email": "maria.garcia@minerva.gov",
    "fullName": "Maria Garcia López",
    "roles": ["ANALISTA"]
  }'
```

**Resposta**:
```json
{
  "success": true,
  "user": {
    "id": "507f1f77bcf86cd799439012",
    "username": "maria.garcia",
    "email": "maria.garcia@minerva.gov",
    "fullName": "Maria Garcia López",
    "roles": ["ANALISTA"],
    "active": true,
    "twoFactorEnabled": false
  },
  "temporaryPassword": "Xy9$mK2#pL5@qW8!",
  "message": "Usuari creat. Contrasenya temporal: Xy9$mK2#pL5@qW8!"
}
```

**Important**: Guarda la contrasenya temporal! No es torna a mostrar.

### Setup 2FA per al Nou Usuari

```bash
# 1. Login amb credencials temporals
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "maria.garcia",
    "password": "Xy9$mK2#pL5@qW8!"
  }'

# El sistema detecta que el 2FA no està configurat

# 2. Configurar 2FA
curl -X POST http://localhost:8080/api/auth/setup-2fa \
  -H "Authorization: Bearer [SESSION_TOKEN]"
```

**Resposta**:
```json
{
  "qrCode": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "secret": "JBSWY3DPEHPK3PXP",
  "message": "Escaneja el QR amb la teva app d'autenticació"
}
```

### Activar 2FA

```bash
# Després d'escanejar el QR, validar amb un codi
curl -X POST http://localhost:8080/api/auth/enable-2fa \
  -H "Authorization: Bearer [SESSION_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{
    "totpCode": "123456"
  }'
```

**Resposta**:
```json
{
  "success": true,
  "message": "2FA activat correctament. Ja pots fer login complet"
}
```

---

## Gestió de Rols

### Assignar Rol

```bash
curl -X POST http://localhost:8080/api/users/507f1f77bcf86cd799439012/roles \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]" \
  -H "Content-Type: application/json" \
  -d '{
    "role": "SUPERVISOR"
  }'
```

### Eliminar Rol

```bash
curl -X DELETE http://localhost:8080/api/users/507f1f77bcf86cd799439012/roles/ANALISTA \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]"
```

### Desactivar Usuari

```bash
curl -X POST http://localhost:8080/api/users/507f1f77bcf86cd799439012/disable \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]"
```

### Activar Usuari

```bash
curl -X POST http://localhost:8080/api/users/507f1f77bcf86cd799439012/enable \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]"
```

---

## Consulta de Logs

### Tots els Logs (Admin/Supervisor)

```bash
curl -X GET "http://localhost:8080/api/audit/logs?page=0&size=50" \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]"
```

### Logs d'un Usuari Específic

```bash
curl -X GET "http://localhost:8080/api/audit/logs/user/507f1f77bcf86cd799439012" \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]"
```

### Logs per Rang de Dates

```bash
curl -X GET "http://localhost:8080/api/audit/logs?from=2025-01-01T00:00:00Z&to=2025-01-09T23:59:59Z" \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]"
```

### Intents de Login Fallits

```bash
curl -X GET "http://localhost:8080/api/audit/logs/failed-logins" \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]"
```

### Activitat Sospitosa

```bash
curl -X GET "http://localhost:8080/api/audit/logs/suspicious" \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]"
```

**Exemple de Resposta**:
```json
{
  "logs": [
    {
      "id": "507f1f77bcf86cd799439015",
      "action": "LOGIN_FAILED",
      "username": "john.doe",
      "timestamp": "2025-01-09T10:15:30Z",
      "ipAddress": "192.168.1.100",
      "success": false,
      "details": "Login fallit: Invalid password",
      "sequenceNumber": 12345,
      "currentHash": "abc123..."
    }
  ],
  "total": 1,
  "page": 0,
  "size": 50
}
```

---

## Verificació d'Integritat

### Verificar Cadena Completa de Logs

```bash
curl -X POST http://localhost:8080/api/audit/verify-integrity \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]"
```

**Resposta si tot és correcte**:
```json
{
  "valid": true,
  "totalLogs": 12345,
  "message": "La cadena de logs és íntegra. Cap manipulació detectada."
}
```

**Resposta si hi ha manipulació**:
```json
{
  "valid": false,
  "totalLogs": 12345,
  "firstInvalidSequence": 5678,
  "message": "ALERTA: Manipulació detectada a partir del log #5678"
}
```

### Verificar Rang de Logs

```bash
curl -X POST http://localhost:8080/api/audit/verify-integrity-range \
  -H "Authorization: Bearer [ACCESS_TOKEN_ADMIN]" \
  -H "Content-Type: application/json" \
  -d '{
    "fromSequence": 1000,
    "toSequence": 2000
  }'
```

---

## Exemple Complet: Flux de Treball Diari

### 1. Admin Matinal

```bash
# Comprovar integritat de logs
curl -X POST http://localhost:8080/api/audit/verify-integrity \
  -H "Authorization: Bearer [TOKEN]"

# Revisar intents fallits de les últimes 24h
curl -X GET "http://localhost:8080/api/audit/logs/failed-logins?since=24h" \
  -H "Authorization: Bearer [TOKEN]"

# Revisar usuaris bloquejats
curl -X GET "http://localhost:8080/api/users/locked" \
  -H "Authorization: Bearer [TOKEN]"
```

### 2. Crear Nou Analista

```bash
# Crear usuari
curl -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer [TOKEN]" \
  -d '{
    "username": "new.analyst",
    "email": "analyst@minerva.gov",
    "fullName": "New Analyst",
    "roles": ["ANALISTA"]
  }'

# Guardar contrasenya temporal → Enviar per canal segur a l'analista
```

### 3. Nou Analista - Primer Login

```bash
# Login amb temporal
→ Retorna SessionToken

# Setup 2FA
→ QR Code

# Activar 2FA
→ Login complet!
```

---

## Resolució de Problemes

### Compte Bloquejat

**Problema**: "El compte està bloquejat"

**Solució** (Admin):
```bash
curl -X POST http://localhost:8080/api/users/[USER_ID]/unlock \
  -H "Authorization: Bearer [ADMIN_TOKEN]"
```

### 2FA Perdut

**Problema**: "He perdut l'accés a la meva app d'autenticació"

**Solució** (Admin):
```bash
curl -X POST http://localhost:8080/api/users/[USER_ID]/reset-2fa \
  -H "Authorization: Bearer [ADMIN_TOKEN]"

# Retorna nou QR code
```

### Token Expirat

**Problema**: "Token expired"

**Solució**:
```bash
# Usar refresh token
curl -X POST http://localhost:8080/api/auth/refresh \
  -d '{"refreshToken": "[REFRESH_TOKEN]"}'
```

### Refresh Token Invàlid

**Problema**: "Refresh token invalid or revoked"

**Causa**: Token revocat, expirat o dispositiu diferent

**Solució**: Fer login de nou

---

## Notes de Seguretat

1. **Mai** compartir tokens en canals insegurs
2. **Mai** guardar access tokens en localStorage
3. **Sempre** usar HTTPS en producció
4. **Rotar** contrasenyes cada 90 dies (recomanat)
5. **Revisar** logs d'auditoria regularment

---

## Recursos Addicionals

- [SECURITY.md](SECURITY.md) - Documentació completa de seguretat
- [README.md](README.md) - Visió general del projecte
- [MongoDB Setup](mongodb-setup.js) - Script de configuració de BD
