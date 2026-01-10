# Configuració del Primer Administrador

Aquest document explica com crear el primer usuari administrador al sistema Minerva.

## Prerequisits

1. **MongoDB** executant-se a `localhost:27017` (sense usuaris)
2. **Backend Quarkus** executant-se a `http://localhost:8080`
3. **Google Authenticator** o **Authy** instal·lat al teu mòbil

## Pas 1: Verificar que el Sistema Necessita Configuració

Primer, comprova si el sistema està buit:

```bash
GET http://localhost:8080/api/setup/needs-setup
```

Resposta esperada:
```json
{
  "needsSetup": true,
  "userCount": 0
}
```

Si `needsSetup` és `false`, ja hi ha usuaris al sistema i no pots usar aquest procés.

## Pas 2: Crear el Primer Admin

Envia una petició per crear l'administrador inicial:

```bash
POST http://localhost:8080/api/setup/first-admin
Content-Type: application/json

{
  "username": "admin",
  "password": "YourSecurePassword123!@#",
  "email": "admin@minerva.gov",
  "fullName": "System Administrator"
}
```

### Requisits de la Contrasenya:
- Mínim 12 caràcters
- Mínim 1 majúscula
- Mínim 1 minúscula
- Mínim 1 número
- Mínim 1 caràcter especial (!@#$%^&*...)

### Resposta Esperada:

```json
{
  "success": true,
  "username": "admin",
  "userId": "507f1f77bcf86cd799439011",
  "totpQrCode": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "message": "Administrador creat correctament! IMPORTANT:\n1. Escaneja el QR code amb Google Authenticator o Authy\n2. Usa l'endpoint POST /api/setup/enable-first-admin-2fa per activar el 2FA\n3. Després podràs fer login amb username, password i codi TOTP"
}
```

## Pas 3: Configurar Google Authenticator

1. **Obre Google Authenticator** (o Authy) al teu mòbil
2. **Prem el botó +** per afegir un nou compte
3. **Escanejar codi QR**:
   - Opció A: Si estàs usant Insomnia/Postman, copia el valor de `totpQrCode` i obre'l en un navegador per veure el QR
   - Opció B: Crea un fitxer HTML temporal:
     ```html
     <!DOCTYPE html>
     <html>
     <body>
       <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..." alt="QR Code">
     </body>
     </html>
     ```
4. **Escaneja el QR code** amb l'app
5. L'app ara mostrarà un **codi de 6 dígits** que canvia cada 30 segons

## Pas 4: Activar el 2FA

Usa el codi de 6 dígits que mostra Google Authenticator per activar el 2FA:

```bash
POST http://localhost:8080/api/setup/enable-first-admin-2fa
Content-Type: application/json

{
  "username": "admin",
  "totpCode": "123456"
}
```

**IMPORTANT**: El codi TOTP canvia cada 30 segons. Assegura't d'usar el codi actual!

### Resposta Esperada:

```json
{
  "success": true,
  "message": "2FA activat correctament! Ara pots fer login amb:\n1. POST /api/auth/login amb username i password\n2. POST /api/auth/verify-2fa amb el userId, sessionToken i codi TOTP"
}
```

## Pas 5: Fer Login

Ara pots fer login amb el procés d'autenticació en dues fases:

### Fase 1: Autenticació amb Credencials

```bash
POST http://localhost:8080/api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "YourSecurePassword123!@#"
}
```

Resposta:
```json
{
  "sessionToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "userId": "507f1f77bcf86cd799439011",
  "requires2FA": true
}
```

### Fase 2: Verificació 2FA

Usa el `sessionToken` i `userId` de la fase 1, juntament amb el codi TOTP actual:

```bash
POST http://localhost:8080/api/auth/verify-2fa
Content-Type: application/json

{
  "userId": "507f1f77bcf86cd799439011",
  "sessionToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "totpCode": "654321"
}
```

Resposta:
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 300,
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "username": "admin",
    "roles": ["ADMIN"],
    "email": "admin@minerva.gov"
  }
}
```

## Pas 6: Usar l'Access Token

Ara pots usar l'`accessToken` per accedir a endpoints protegits:

```bash
GET http://localhost:8080/api/users
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Ús amb Insomnia

Si estàs usant la col·lecció d'Insomnia (`Insomnia_Minerva_API.json`):

1. Importa la col·lecció
2. Configura les variables d'entorn:
   - `base_url`: `http://localhost:8080`
   - `admin_username`: `admin`
   - `admin_password`: La teva contrasenya
3. Usa la carpeta **"0 - Setup"** per configurar el primer admin
4. Usa la carpeta **"1 - Authentication"** per fer login

## Troubleshooting

### Error: "Codi TOTP incorrecte"

- **Problema**: L'hora del teu ordinador/mòbil no està sincronitzada
- **Solució**:
  - Windows: Ves a Configuració → Hora i idioma → Sincronitzar l'hora
  - Google Authenticator: Configuració → Correcció d'hora per als codis

### Error: "Aquest endpoint està desactivat"

- **Problema**: Ja hi ha usuaris al sistema
- **Solució**: Si vols tornar a començar, esborra tots els usuaris de MongoDB:
  ```javascript
  // A mongosh:
  use minerva_db
  db.User.deleteMany({})
  db.RefreshToken.deleteMany({})
  db.AuditLog.deleteMany({})
  ```

### Error: "Password does not meet requirements"

- **Problema**: La contrasenya no és prou forta
- **Solució**: Assegura't que té:
  - Mínim 12 caràcters
  - Majúscules, minúscules, números i caràcters especials

## Seguretat

### IMPORTANT:

1. **Canvia la contrasenya** després del primer login
2. **Mantén el secret** del QR code (no el comparteixis)
3. **Fes backup** del secret TOTP (Google Authenticator → Configuració → Exportar comptes)
4. **No perdis l'accés** a Google Authenticator (si el perds, necessitaràs accés directe a MongoDB per restablir el 2FA)

## Següents Passos

Un cop hagis configurat l'admin:

1. **Crea més usuaris** amb `POST /api/users`
2. **Assigna rols** segons les necessitats
3. **Configura 2FA** per tots els usuaris
4. **Revisa els logs d'auditoria** amb `GET /api/audit/logs`

## Endpoints de Setup

Aquests endpoints només funcionen en condicions específiques:

| Endpoint | Quan funciona | Propòsit |
|----------|---------------|----------|
| `GET /api/setup/needs-setup` | Sempre | Comprovar si cal configuració |
| `POST /api/setup/first-admin` | userCount == 0 | Crear primer admin |
| `POST /api/setup/enable-first-admin-2fa` | userCount == 1 i 2FA desactivat | Activar 2FA del primer admin |

Després de crear més usuaris, aquests endpoints retornaran errors de seguretat.
