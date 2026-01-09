# Minerva Security System

Sistema complet d'autenticació i autorització ultrasegur pensat per entorns governamentals d'intel·ligència amb múltiples nivells d'autorització.

## 🔒 Característiques Principals

- **Autenticació Forta**: Argon2id + 2FA obligatori (TOTP/U2F)
- **Tokens Segurs**: JWT (RS256) + Refresh tokens amb rotació automàtica
- **RBAC**: Control d'accés basat en rols (ADMIN, SUPERVISOR, ANALISTA, CONTRIBUIDOR)
- **Logs Immutables**: Sistema tipus blockchain per auditories
- **Seguretat en Profunditat**: Rate limiting, bloqueig de comptes, headers de seguretat
- **Sense Registre Públic**: Només administradors poden crear usuaris

## 🏗️ Arquitectura

### Backend
- **Framework**: Quarkus (Java 17)
- **Base de Dades**: MongoDB 7.0
- **Autenticació**: JWT (RS256), Argon2id, TOTP (RFC 6238)
- **API**: RESTful amb validació i protecció RBAC

### Frontend (En desenvolupament)
- **Framework**: Angular (última versió estable)
- **Autenticació**: Formulari en dues fases (credencials + 2FA)
- **Panell Admin**: Gestió d'usuaris, rols i logs

## 📁 Estructura del Projecte

```
minerva/
├── backend/                          # Backend Quarkus
│   ├── src/main/java/cat/minerva/
│   │   ├── model/                    # Models de dades
│   │   │   ├── User.java
│   │   │   ├── UserRole.java
│   │   │   ├── RefreshToken.java
│   │   │   └── AuditLog.java
│   │   ├── repository/               # Repositoris MongoDB
│   │   ├── service/                  # Serveis de negoci
│   │   │   ├── AuthService.java
│   │   │   └── UserService.java
│   │   ├── security/                 # Components de seguretat
│   │   │   ├── PasswordHashService.java  # Argon2id
│   │   │   ├── TotpService.java          # 2FA (TOTP)
│   │   │   └── TokenService.java         # JWT + Refresh
│   │   ├── audit/                    # Sistema d'auditoria
│   │   │   └── AuditService.java
│   │   ├── resource/                 # Endpoints REST
│   │   └── dto/                      # Data Transfer Objects
│   ├── src/test/java/cat/minerva/  # Tests (84+ tests)
│   │   ├── security/                 # Tests unitaris de seguretat
│   │   │   ├── PasswordHashServiceTest.java  # 15 tests
│   │   │   ├── TotpServiceTest.java          # 18 tests
│   │   │   ├── TokenServiceTest.java         # 13 tests
│   │   │   └── SecurityTest.java             # 15 tests OWASP
│   │   └── resource/                 # Tests d'integració
│   │       ├── AuthResourceIT.java           # 8 tests
│   │       └── UserResourceIT.java           # 15 tests
│   ├── src/main/resources/
│   │   ├── application.properties
│   │   └── keys/                     # Claus JWT (NO a Git!)
│   ├── TESTING.md                    # Guia de testing
│   └── pom.xml
├── frontend/                         # Frontend Angular (en desenvolupament)
├── .github/workflows/                # GitHub Actions CI/CD
│   └── backend-tests.yml             # Tests automàtics + coverage
├── .git-hooks/                       # Git hooks personalitzats
│   └── pre-commit                    # Tests abans de commit
├── mongodb-setup.js                  # Script de configuració MongoDB
├── docker-compose.yml                # Desplegament amb Docker
├── scripts/
│   └── generate-keys.sh              # Generador de claus JWT
├── install-hooks.sh                  # Instal·lador de git hooks
├── SECURITY.md                       # Documentació de seguretat
├── USAGE_EXAMPLES.md                 # Exemples d'ús de l'API
├── DEPLOYMENT.md                     # Guia de desplegament
└── README.md
```

## 🚀 Quick Start

### 1. Prerequisits

```bash
# Java 17+
java -version

# Maven 3.8+
mvn -version

# MongoDB 7.0+
mongod --version

# Docker (opcional)
docker --version
```

### 2. Clonar i Configurar

```bash
# Clonar repositori
git clone https://github.com/yourgov/minerva.git
cd minerva

# Copiar variables d'entorn
cp .env.example .env

# Generar claus JWT
./scripts/generate-keys.sh
```

### 3. Executar amb Docker Compose (Recomanat)

```bash
# Aixecar tots els serveis
docker-compose up -d

# Verificar estat
docker-compose ps

# Veure logs
docker-compose logs -f backend
```

L'aplicació estarà disponible a:
- Backend API: http://localhost:8080
- Health Check: http://localhost:8080/health
- MongoDB: localhost:27017

### 4. Executar Manualment

```bash
# 1. Iniciar MongoDB
docker run -d --name minerva-mongo -p 27017:27017 mongo:7.0

# 2. Configurar MongoDB
docker exec -i minerva-mongo mongosh < mongodb-setup.js

# 3. Executar backend
cd backend
./mvnw quarkus:dev
```

## 🔐 Seguretat Implementada

### 1. Autenticació Multi-Factor

- **Argon2id**: Hashing de contrasenyes (guanyador Password Hashing Competition 2015)
  - Iteracions: 3, Memòria: 64MB, Paral·lelisme: 4
  - Salt únic aleatori per cada usuari
  - Resistent a atacs GPU i ASIC

- **2FA Obligatori**: TOTP (RFC 6238)
  - Compatible amb Google Authenticator, Authy, etc.
  - Codis de 6 dígits renovats cada 30 segons
  - Preparació per U2F/FIDO2 (YubiKey, etc.)

### 2. Sistema de Tokens de Doble Capa

- **Access Token (JWT)**:
  - Vida curta: 5-10 minuts
  - Signat amb RS256 (clau asimètrica)
  - No es pot revocar (per això és curt)
  - Conté userId, username, roles

- **Refresh Token**:
  - Vida llarga: 24 hores
  - Emmagatzemat com hash SHA-256 a MongoDB
  - **Rotació automàtica**: cada ús genera un nou token
  - Vinculat a dispositiu (fingerprint)
  - Detecció de reutilització (possible atac)

### 3. Logs Immutables (Tipus Blockchain)

Cada entrada de log conté:
```
currentHash = SHA256(previousHash + contingut)
```

Si algú modifica un log, la cadena es trenca i és detectable.

**Què es registra:**
- ✅ Tots els intents de login (èxit/fallida)
- ✅ Validació 2FA
- ✅ Creació/modificació d'usuaris
- ✅ Canvis de rols i permisos
- ✅ Bloqueig/desbloqueig de comptes
- ✅ Activitat sospitosa

### 4. Proteccions Addicionals

- ✅ **Rate Limiting**: Màx 10 intents/minut per IP
- ✅ **Bloqueig de Compte**: 5 intents fallits → bloqueig 30 min
- ✅ **Headers de Seguretat**: CSP, HSTS, X-Frame-Options, etc.
- ✅ **Prevenció d'Injeccions**: NoSQL Injection, XSS, CSRF
- ✅ **Deny-by-Default**: Tot denegat excepte explícitament permès

## 📖 Exemples d'Ús

### Login Complet (2 Fases)

```bash
# Fase 1: Credencials
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "john.doe", "password": "MyPass123!@#"}'

# Resposta: {"pending2FA": true, "sessionToken": "..."}

# Fase 2: 2FA
curl -X POST http://localhost:8080/api/auth/verify-2fa \
  -H "Authorization: Bearer [sessionToken]" \
  -d '{"userId": "...", "totpCode": "123456"}'

# Resposta: {"accessToken": "...", "refreshToken": "..."}
```

### Renovar Tokens

```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -d '{"refreshToken": "..."}'
```

### Crear Usuari (Admin)

```bash
curl -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer [adminToken]" \
  -d '{
    "username": "maria.garcia",
    "email": "maria@gov.cat",
    "roles": ["ANALISTA"]
  }'
```

Més exemples: [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md)

## 📚 Documentació

- **[SECURITY.md](SECURITY.md)**: Documentació completa de seguretat i decisions tècniques
- **[USAGE_EXAMPLES.md](USAGE_EXAMPLES.md)**: Exemples pràctics d'ús de l'API
- **[DEPLOYMENT.md](DEPLOYMENT.md)**: Guia de desplegament en producció
- **[backend/TESTING.md](backend/TESTING.md)**: Guia completa de testing i code coverage

## 🛠️ Tecnologies Utilitzades

| Component | Tecnologia | Versió | Raó d'Elecció |
|-----------|-----------|--------|---------------|
| Backend | Quarkus | 3.6.4 | Alt rendiment, natiu a Kubernetes |
| Base de Dades | MongoDB | 7.0 | Escalabilitat, flexibilitat |
| Hashing | Argon2id | 2.11 | Estàndard OWASP, resistent a GPU |
| 2FA | TOTP (RFC 6238) | - | Estàndard universal |
| JWT | SmallRye JWT | - | Integració nativa Quarkus |
| QR Codes | ZXing | 3.5.2 | Configuració 2FA |
| Rate Limiting | Resilience4j | 2.1.0 | Protecció contra força bruta |
| Testing | JUnit 5 + Mockito | 5.7.0 | Testing framework complet |
| Integration Tests | REST Assured | - | Testing API RESTful |
| Code Coverage | JaCoCo | 0.8.11 | Cobertura de codi (≥70%) |
| CI/CD | GitHub Actions | - | Integració contínua |

## 🔧 Desenvolupament

### Suite de Tests Automàtics

El projecte inclou una suite completa de **84+ tests** que cobreixen:

- ✅ **Tests Unitaris** (46 tests):
  - PasswordHashService (15 tests) - Argon2id, validació de passwords
  - TotpService (18 tests) - 2FA TOTP, RFC 6238 compliance
  - TokenService (13 tests) - JWT, refresh tokens, rotació

- ✅ **Tests d'Integració** (23 tests):
  - AuthResource (8 tests) - Flux complet de login 2FA
  - UserResource (15 tests) - Gestió d'usuaris, RBAC

- ✅ **Tests de Seguretat** (15 tests):
  - OWASP Top 10 coverage
  - NoSQL injection, XSS, CSRF, etc.

### Executar Tests

```bash
cd backend

# Tots els tests (unitaris + integració + seguretat)
./mvnw test

# Només tests unitaris
./mvnw test -Dtest="*Test"

# Només tests d'integració
./mvnw test -Dtest="*IT"

# Només tests de seguretat
./mvnw test -Dtest=SecurityTest

# Generar informe de code coverage
./mvnw clean test jacoco:report
# Informe: target/site/jacoco/index.html
```

**Code Coverage**: JaCoCo configurat amb mínim 70% de cobertura de línies.

### CI/CD

GitHub Actions configurat per executar automàticament:
- ✅ Tests unitaris en cada push/PR
- ✅ Tests d'integració amb MongoDB
- ✅ Tests de seguretat OWASP
- ✅ Verificació de code coverage (≥70%)
- ✅ Informe de coverage a Codecov

### Pre-commit Hooks

Instal·la hooks per executar tests abans de cada commit:

```bash
# Instal·lar hooks
./install-hooks.sh

# Els tests s'executaran automàticament abans de cada commit
git commit -m "Your message"

# Per saltar hooks temporalment (NO recomanat)
git commit --no-verify
```

### Mode Desenvolupament

```bash
./mvnw quarkus:dev
```

Amb hot-reload automàtic en canvis de codi.

### Documentació de Tests

Consulta [backend/TESTING.md](backend/TESTING.md) per:
- Guia completa d'execució de tests
- Descripció detallada de cada test
- Best practices per escriure nous tests
- Debugging i troubleshooting

## 🚢 Desplegament en Producció

Consulta la guia completa: [DEPLOYMENT.md](DEPLOYMENT.md)

Checklist ràpid:
- [ ] Tots els tests passen (84+ tests)
- [ ] Code coverage ≥70% verificat
- [ ] Tests de seguretat OWASP passen
- [ ] MongoDB amb autenticació i TLS
- [ ] Claus JWT de 4096 bits generades
- [ ] HTTPS configurat amb certificat vàlid
- [ ] Firewall configurat
- [ ] Backups automàtics de logs d'auditoria
- [ ] Monitorització i alertes actives
- [ ] CI/CD pipeline executant-se correctament

## 🤝 Contribució

Aquest és un projecte de seguretat crítica. Totes les contribucions han de:
1. Passar revisió de seguretat
2. Incloure tests exhaustius
3. Documentar decisions de seguretat
4. Seguir les millors pràctiques OWASP

## 📄 Llicència

[Definir llicència segons política governamental]

## ⚠️ Advertències de Seguretat

- **MAI** pujar claus JWT a control de versions
- **MAI** guardar access tokens en localStorage
- **SEMPRE** usar HTTPS en producció
- **SEMPRE** canviar contrasenyes per defecte
- **SEMPRE** verificar integritat de logs periòdicament

## 📞 Suport

Per qüestions de seguretat o incidents, contacta:
- Email: security@yourgov.cat
- Telèfon d'emergències: [DEFINIR]

---

**Minerva Security System** - Seguretat de nivell governamental per a entorns d'intel·ligència crítics.
