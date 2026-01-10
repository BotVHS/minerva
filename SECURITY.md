# Minerva Security System - Documentació de Seguretat

## Visió General

Minerva és un sistema d'autenticació i autorització dissenyat per entorns governamentals d'intel·ligència amb els màxims estàndards de seguretat. Aquest document explica totes les decisions de seguretat i com s'han implementat.

## Índex

1. [Autenticació](#autenticació)
2. [Gestió de Contrasenyes](#gestió-de-contrasenyes)
3. [2FA (Two-Factor Authentication)](#2fa-two-factor-authentication)
4. [Sistema de Tokens](#sistema-de-tokens)
5. [Autorització (RBAC)](#autorització-rbac)
6. [Logs d'Auditoria Immutables](#logs-dauditoria-immutables)
7. [Proteccions Addicionals](#proteccions-addicionals)
8. [MongoDB i Seguretat de Dades](#mongodb-i-seguretat-de-dades)
9. [Consideracions de Desplegament](#consideracions-de-desplegament)

---

## Autenticació

### Procés d'Autenticació en Dues Fases

El sistema implementa un **procés d'autenticació en dues fases obligatori**:

#### Fase 1: Validació de Credencials
1. L'usuari envia `username` i `password`
2. El sistema verifica:
   - Usuari existeix i està actiu
   - Compte no està bloquejat
   - Contrasenya és correcta (Argon2id)
3. Si és correcte, retorna un **SessionToken temporal**
4. Aquest token només serveix per accedir a la fase 2

#### Fase 2: Validació 2FA
1. L'usuari envia el `SessionToken` + codi TOTP
2. El sistema verifica el codi TOTP
3. Si és correcte, retorna:
   - **Access Token** (JWT, 5-10 min)
   - **Refresh Token** (24h, emmagatzemat xifrat)

### Per què Dues Fases?

- **Seguretat en Profunditat**: Comprometre només la contrasenya no dona accés
- **2FA Obligatori**: Impossible fer login sense 2FA
- **Separació de Concerniments**: Cada fase valida un factor diferent
- **Auditoria Granular**: Sabem exactament on falla l'autenticació

---

## Gestió de Contrasenyes

### Argon2id: L'Estàndard d'Or

Utilitzem **Argon2id** per hashear contrasenyes, l'algoritme recomanat per OWASP des de 2015.

#### Per què Argon2id?

1. **Guanyador del Password Hashing Competition** (2015)
2. **Resistent a atacs GPU/ASIC**: Requereix molta memòria
3. **Protecció contra side-channel attacks**: Variant híbrida (Argon2i + Argon2d)
4. **Configurable**: Podem ajustar la dificultat segons necessitats

#### Paràmetres Utilitzats

```
Type: Argon2id
Iterations: 3 (t_cost)
Memory: 65536 KB (64 MB)
Parallelism: 4 threads
Salt: Generat automàticament (aleatori)
```

#### Format del Hash

```
$argon2id$v=19$m=65536,t=3,p=4$[salt]$[hash]
```

**Important**: El salt està inclòs en el hash. Cada usuari té un salt únic i aleatori.

### Política de Contrasenyes

Contrasenyes fortes obligatòries:
- **Mínim 12 caràcters**
- Almenys 1 majúscula
- Almenys 1 minúscula
- Almenys 1 dígit
- Almenys 1 caràcter especial
- **NO** contrasenyes comunes (validació contra llista)
- **NO** patrons repetitius o seqüències

### Contrasenyes Temporals

Quan un admin crea un usuari:
1. Es genera una contrasenya temporal aleatòria
2. Compleix la política de seguretat
3. L'usuari **ha de canviar-la** en el primer login
4. El canvi queda registrat en els logs

---

## 2FA (Two-Factor Authentication)

### TOTP (RFC 6238)

Implementem **TOTP (Time-based One-Time Password)** segons RFC 6238.

#### Funcionament

1. **Setup Inicial**:
   - Servidor genera secret aleatori de 160 bits (Base32)
   - Genera QR code amb URI `otpauth://totp/...`
   - Usuari escaneja amb app (Google Authenticator, Authy, etc.)
   - Usuari valida amb primer codi

2. **Login Posterior**:
   - App genera codi de 6 dígits cada 30 segons
   - Usuari introdueix el codi
   - Servidor valida amb finestra de ±1 període (90s total)

#### Paràmetres TOTP

```
Secret Size: 160 bits
Algorithm: SHA-1 (estàndard RFC 6238)
Digits: 6
Period: 30 segons
Time Window: ±1 període (per clock skew)
```

#### Compatibilitat

Compatible amb totes les apps estàndard:
- Google Authenticator
- Microsoft Authenticator
- Authy
- 1Password
- Bitwarden
- FreeOTP

### U2F / FIDO2 (Futur)

El model `User` ja té el camp `u2fPublicKey` preparat per suportar:
- Claus de seguretat física (YubiKey, etc.)
- Autenticació biométrica (Touch ID, Face ID)
- Passkeys (WebAuthn)

---

## Sistema de Tokens

### Arquitectura de Dos Nivells

#### 1. Access Token (JWT)

**Propòsit**: Autenticació de cada request

**Característiques**:
- Format: JWT (JSON Web Token)
- Signatura: RS256 (clau asimètrica)
- Duració: **5-10 minuts** (molt curt)
- Emmagatzematge: **Només memòria** al client (mai localStorage)
- **No es pot revocar** (per això és curt)

**Claims**:
```json
{
  "iss": "https://min3rva.cat",
  "sub": "userId",
  "upn": "username",
  "groups": ["ADMIN", "ANALISTA"],
  "iat": 1234567890,
  "exp": 1234568190
}
```

#### 2. Refresh Token

**Propòsit**: Obtenir nous Access Tokens sense reautenticar

**Característiques**:
- Format: String aleatori de 256 bits (Base64)
- Emmagatzematge: **Hash SHA-256** a MongoDB
- Duració: **24 hores**
- **Pot revocar-se** immediatament
- **Rotació automàtica**: cada ús genera un nou token

### Seguretat dels Refresh Tokens

#### 1. Només Hash a la BD

```
Token Original: "abc123..." (enviat al client)
Guardat a BD: SHA-256("abc123...") = "7a8b9c..."
```

**Per què?** Si la BD es compromet, els tokens no són utilitzables.

#### 2. Vinculació a Dispositiu

Cada token està vinculat a un `deviceFingerprint`:
```
fingerprint = SHA-256(User-Agent)
```

**Protecció**: Un token robat no funciona des d'un altre dispositiu.

#### 3. Rotació Automàtica

Cada cop que s'usa un Refresh Token:
1. Es genera un **nou** Refresh Token
2. L'**anterior** s'invalida
3. El nou està vinculat a l'anterior (cadena)

**Protecció contra replay attacks**: Si algú reutilitza un token vell, es detecta i es revoquen tots els tokens de l'usuari.

#### 4. Detecció de Reutilització

Si un token es fa servir **més d'un cop**:
- És un **possible atac** (robatori de token)
- El sistema **revoca tots** els tokens de l'usuari
- Es registra com activitat sospitosa
- L'usuari ha de fer login de nou

### Flux Complet de Tokens

```
1. Login → Access (5 min) + Refresh (24h)
2. Access expira → Usa Refresh
3. Refresh → Nou Access + Nou Refresh (rotació)
4. L'anterior Refresh s'invalida
5. Repetir des de (2)
```

---

## Autorització (RBAC)

### Role-Based Access Control

Sistema de rols jeràrquic:

```
ADMIN
  └─ Accés total
  └─ Crear/modificar usuaris
  └─ Assignar rols
  └─ Veure tots els logs

SUPERVISOR
  └─ Supervisar operacions
  └─ Veure logs (read-only)
  └─ Monitorar activitats

ANALISTA
  └─ Accés a dades
  └─ Eines d'anàlisi
  └─ Exportar informes

CONTRIBUIDOR
  └─ Accés bàsic
  └─ Contribuir dades
  └─ Permisos limitats
```

### Principi de Mínim Privilegi

- Usuaris nous: **CONTRIBUIDOR** per defecte
- Elevació de permisos: Només per admins
- Cada acció comprova el rol necessari
- **Deny-by-default**: Tot denegat excepte explícitament permès

### Implementació

A nivell de codi:
```java
@RolesAllowed("ADMIN")
public void createUser(...) { ... }

@RolesAllowed({"ADMIN", "SUPERVISOR"})
public void viewAuditLogs(...) { ... }
```

---

## Logs d'Auditoria Immutables

### Sistema Tipus Blockchain

Els logs d'auditoria són **immutables** i **resistents a manipulacions** mitjançant una tècnica inspirada en blockchain.

#### Funcionament

Cada entrada de log conté:
1. **Contingut**: acció, usuari, timestamp, IP, etc.
2. **previousHash**: hash de l'entrada anterior
3. **currentHash**: hash d'aquesta entrada

```
Log 1: hash = SHA256("" + content1)
Log 2: hash = SHA256(hash1 + content2)
Log 3: hash = SHA256(hash2 + content3)
...
```

#### Per què és Immutable?

Si algú intenta modificar el **Log 2**:
- El seu hash canvia: `hash2' ≠ hash2`
- Però `hash3` depèn de `hash2`
- La cadena es trenca: `hash3` ja no és vàlid
- **Detecció automàtica** de manipulació

#### Verificació d'Integritat

```java
boolean isValid = auditService.verifyIntegrity();
// Recalcula tots els hashs i comprova la cadena
```

Es pot executar periòdicament per assegurar que cap log s'ha manipulat.

### Què es Registra?

**TOTES** les accions crítiques:
- ✅ Login (èxit/fallida)
- ✅ Validació 2FA
- ✅ Creació/modificació d'usuaris
- ✅ Canvi de rols
- ✅ Canvi de contrasenyes
- ✅ Bloqueig/desbloqueig de comptes
- ✅ Accés a recursos sensibles
- ✅ Activitat sospitosa
- ✅ Logout

### Informació per Cada Log

```java
{
  action: "LOGIN_SUCCESS",
  userId: "507f1f77bcf86cd799439011",
  username: "john.doe",
  userRoles: "[ADMIN]",
  timestamp: "2025-01-09T10:15:30Z",
  ipAddress: "192.168.1.100",
  userAgent: "Mozilla/5.0...",
  deviceFingerprint: "7a8b9c...",
  success: true,
  details: "Login exitós des de 192.168.1.100",
  sequenceNumber: 12345,
  previousHash: "abc123...",
  currentHash: "def456..."
}
```

### Col·lecció Append-Only

A MongoDB:
- **Només INSERT**, mai UPDATE o DELETE
- Índexs per cerca ràpida
- TTL opcional per logs antics (però sempre després de backup)

---

## Proteccions Addicionals

### 1. Bloqueig de Compte

**Regla**: Després de **5 intents fallits**, el compte es bloqueja durant **30 minuts**.

```java
if (user.failedLoginAttempts >= 5) {
    user.lockAccount(1800); // 30 minuts
    auditService.logAccountLocked(...);
}
```

**Desbloqueig**:
- Automàtic després del temps
- Manual per un administrador

### 2. Rate Limiting

**Implementat amb Resilience4j**:
- Màxim 10 intents de login per IP en 60 segons
- Màxim 5 requests per API endpoint per segon
- Bloqueig temporal si se supera

### 3. Protecció contra Injeccions

**NoSQL Injection**:
- MongoDB Panache usa queries paramètriques
- Validació d'entrada amb Bean Validation
- Escapament automàtic

**XSS Prevention**:
- Headers de seguretat (CSP, X-XSS-Protection)
- Sanitització d'output
- Content-Type correctes

### 4. CSRF Protection

- Tokens CSRF en formularis
- SameSite cookies
- Validació d'origen

### 5. Headers de Seguretat

```properties
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

---

## MongoDB i Seguretat de Dades

### Configuració de Seguretat

1. **Autenticació Habilitada**:
   ```
   security:
     authorization: enabled
   ```

2. **TLS/SSL**:
   ```
   net:
     tls:
       mode: requireTLS
   ```

3. **Usuaris amb Permisos Mínims**:
   - Usuari app: `readWrite` només a `minerva_db`
   - Usuari admin: Només per manteniment

### Índexs per Rendiment

Tots els camps de cerca freqüent tenen índex:
- `users.username` (únic)
- `users.email`
- `refresh_tokens.tokenHash` (únic)
- `audit_logs.sequenceNumber` (únic)
- `audit_logs.userId + timestamp`

### Backup i Recuperació

**Crítica**: Els logs d'auditoria són **immutables i legalment necessaris**.

1. **Backup diari** de la col·lecció `audit_logs`
2. **Backup incremental** cada 6 hores
3. **Retenció**: Mínim 7 anys (requisit legal)
4. **Verificació** d'integritat després de cada backup

---

## Consideracions de Desplegament

### Entorn de Producció

#### 1. Generar Claus RSA

```bash
# Clau privada (signar JWT)
openssl genrsa -out private-key.pem 2048

# Clau pública (verificar JWT)
openssl rsa -in private-key.pem -pubout -out public-key.pem

# Copiar a /keys/
mkdir -p /keys
mv *.pem /keys/
chmod 600 /keys/private-key.pem
chmod 644 /keys/public-key.pem
```

#### 2. Variables d'Entorn

```bash
export MONGODB_USER=minerva_app
export MONGODB_PASSWORD=$(openssl rand -base64 32)
export JWT_ISSUER=https://min3rva.cat
```

#### 3. HTTPS Obligatori

- Certificat SSL/TLS vàlid
- Redirect automàtic HTTP → HTTPS
- HSTS habilitada

#### 4. Firewall

```bash
# Només HTTPS
ufw allow 443/tcp

# MongoDB només localhost o xarxa interna
ufw allow from 10.0.0.0/8 to any port 27017
```

### Monitorització

1. **Logs d'aplicació**: Revisar diàriament
2. **Intents fallits**: Alerta si > 100/hora
3. **Comptes bloquejats**: Notificar admins
4. **Activitat sospitosa**: Alerta immediata
5. **Integritat dels logs**: Verificació setmanal

### Manteniment

1. **Rotació de claus JWT**: Cada 90 dies
2. **Neteja de tokens expirats**: Diària (automàtica)
3. **Revisió d'usuaris inactius**: Mensual
4. **Actualitzacions de seguretat**: Immediates

---

## Resum de Decisions Clau

| Component | Tecnologia | Raó |
|-----------|-----------|-----|
| **Hashing** | Argon2id | Estàndard OWASP, resistent a GPU |
| **2FA** | TOTP (RFC 6238) | Estàndard, compatible amb totes les apps |
| **Tokens** | JWT (RS256) | Estàndard, signat asimètric |
| **Refresh** | Random + SHA256 | Alt entropia, hash a BD |
| **Logs** | Blockchain-like | Immutabilitat verificable |
| **RBAC** | Roles + Permisos | Flexibilitat i simplicitat |
| **BD** | MongoDB | Escalabilitat, flexibilitat de schema |

---

## Compliment de Requisits

✅ **Autenticació**: Argon2id + 2FA obligatori
✅ **Sessions**: Access tokens curts + Refresh amb rotació
✅ **Autorització**: RBAC amb 4 rols
✅ **Auditoria**: Logs immutables tipus blockchain
✅ **Proteccions**: Rate limiting, bloqueig, headers, validació
✅ **Mantenibilitat**: Codi modular, comentat, documentat

---

## Contacte i Suport

Per qüestions de seguretat, contacta amb l'equip de seguretat de Minerva.

**IMPORTANT**: Mai comparteixis secrets, claus o tokens en canals no segurs.
