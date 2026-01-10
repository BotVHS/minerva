# 🧪 Guia d'Ús d'Insomnia per Minerva API

## 📥 Importar la Col·lecció

1. **Descarrega Insomnia** (si no el tens): https://insomnia.rest/download
2. **Obre Insomnia**
3. Clica **"Create" → "Import From" → "File"**
4. Selecciona el fitxer `Insomnia_Minerva_API.json`
5. La col·lecció "Minerva Security API" apareixerà amb tots els endpoints

## 🔧 Configurar Variables d'Entorn

Després d'importar, veuràs les variables a la part superior:

| Variable | Valor per Defecte | Descripció |
|----------|------------------|------------|
| `base_url` | `http://localhost:8080` | URL base de l'API |
| `access_token` | (buit) | S'omplirà després del login |
| `refresh_token` | (buit) | S'omplirà després del login |
| `session_token` | (buit) | S'omplirà després Phase 1 |
| `user_id` | (buit) | S'omplirà després Phase 1 |
| `admin_username` | `admin` | Canvia pel teu usuari |
| `admin_password` | `Admin123!@#` | Canvia per la teva contrasenya |

## 🚀 Flux de Treball Complet

### 1️⃣ Login - Fase 1

📂 **Authentication → 1️⃣ Login - Phase 1**

1. Assegura't que `admin_username` i `admin_password` són correctes
2. Clica **"Send"**
3. Resposta esperada:
   ```json
   {
     "pending2FA": true,
     "sessionToken": "eyJhbGci...",
     "userId": "507f1f77bcf86cd799439011",
     "message": "Introdueix el codi 2FA"
   }
   ```
4. **IMPORTANT:** Copia `sessionToken` i `userId`:
   - Clica la icona d'entorn (part superior dreta)
   - Enganxa els valors a les variables corresponents

### 2️⃣ Login - Fase 2

📂 **Authentication → 2️⃣ Login - Phase 2**

1. Obre la teva app d'autenticació (Google Authenticator, Authy, etc.)
2. Copia el codi de 6 dígits
3. Al body de la petició, substitueix `123456` pel codi real
4. Clica **"Send"**
5. Resposta esperada:
   ```json
   {
     "success": true,
     "accessToken": "eyJhbGci...",
     "refreshToken": "7a8b9c0d...",
     "user": {...}
   }
   ```
6. **Copia els tokens** a les variables d'entorn:
   - `access_token` → valor de `accessToken`
   - `refresh_token` → valor de `refreshToken`

### 3️⃣ Provar Endpoints Protegits

Ara pots provar qualsevol endpoint! Tots usen automàticament `{{ _.access_token }}`.

**Exemples:**

📂 **User Management → 📋 List All Users**
- Només clica **"Send"**
- Veuràs tots els usuaris del sistema

📂 **User Management → ➕ Create User**
- Modifica el body amb les dades del nou usuari
- Clica **"Send"**
- **GUARDA** la contrasenya temporal que retorna!

📂 **Audit Logs → 📜 Get All Logs**
- Veuràs tots els logs d'auditoria
- Prova diferents filtres modificant els query params

## 🔄 Renovar Tokens (cada 5-10 min)

Quan l'access token expiri:

📂 **Authentication → 🔄 Refresh Tokens**

1. Clica **"Send"**
2. Rebràs nous tokens
3. **Actualitza** les variables d'entorn amb els nous valors

## 📋 Estructura de la Col·lecció

```
Minerva Security API/
├── 🔐 Authentication
│   ├── 1️⃣ Login - Phase 1 (Credentials)
│   ├── 2️⃣ Login - Phase 2 (2FA Validation)
│   ├── 🔄 Refresh Tokens
│   └── 🚪 Logout
│
├── 👥 User Management (ADMIN)
│   ├── ➕ Create User
│   ├── 📋 List All Users
│   ├── 🔍 Get User by ID
│   ├── ⭐ Assign Role to User
│   ├── ❌ Remove Role from User
│   ├── ✅ Enable User
│   ├── 🚫 Disable User
│   ├── 🔓 Unlock User Account
│   └── 🔄 Reset 2FA
│
├── 📋 Audit Logs (ADMIN/SUPERVISOR)
│   ├── 📜 Get All Logs
│   ├── 👤 Get User Logs
│   ├── ❌ Failed Login Attempts
│   ├── ⚠️ Suspicious Activity
│   ├── 👑 Admin Actions
│   └── 🔒 Verify Log Integrity
│
└── 🏥 Health & Info
    ├── 💚 Health Check
    ├── 🟢 Liveness
    └── 🔵 Readiness
```

## 💡 Tips i Trucs

### Copiar Valors Ràpidament

Quan rebis una resposta:
1. Clica amb botó dret sobre el valor
2. Selecciona **"Copy Value"**
3. Vés a Environment → Enganxa el valor

### Usar Variables a les URLs

Ja està configurat! Tots els endpoints usen `{{ _.base_url }}`.

Si canvies de servidor (ex: producció), només canvia `base_url` a:
```
https://min3rva.cat
```

### Veure Descripció dels Endpoints

Cada endpoint té una **descripció detallada** amb:
- Què fa
- Resposta esperada
- Notes importants
- Següents passos

Clica la icona 📄 per veure-la.

### Probar amb Diferents Usuaris

Per provar amb un usuari diferent:
1. Crea l'usuari amb **Create User**
2. Canvia `admin_username` i `admin_password` a les variables
3. Fes login de nou

## 🎯 Casos d'Ús Comuns

### Crear i Configurar un Nou Usuari Complet

1. **Crear usuari** → `Create User`
2. **Guardar contrasenya temporal**
3. **Assignar rols** → `Assign Role to User`
4. L'usuari fa login amb la contrasenya temporal
5. **Configurar 2FA** (des del frontend o via API)

### Investigar Intents de Login Sospitosos

1. **Failed Login Attempts** → Veure tots els fallits
2. **Suspicious Activity** → Activitat anòmala
3. **Get User Logs** → Logs d'un usuari específic
4. Si cal, **Unlock User Account** o **Disable User**

### Verificar Integritat del Sistema

1. **Verify Log Integrity** → Comprovar manipulacions
2. Si `valid: false` → ALERTA! Investigar immediatament
3. **Admin Actions** → Veure qui ha fet què

### Gestionar Sessions

1. **Login** → Obté tokens
2. Quan expira → **Refresh Tokens**
3. Al final del dia → **Logout** (revoca refresh token)

## 🐛 Troubleshooting

### Error: "Failed to read public key"

- Assegura't que les claus JWT estan generades
- Ubicació: `backend/src/main/resources/keys/`

### Error: "Unauthorized"

- Verifica que `access_token` està configurat
- Potser ha expirat → Usa **Refresh Tokens**

### Error: "User not found"

- L'usuari encara no existeix
- Crea'l primer amb **Create User**

### Error: "2FA validation failed"

- Codi TOTP incorrecte o expirat (30 segons)
- Comprova que el rellotge del servidor i client estan sincronitzats

## 📚 Recursos Addicionals

- **SECURITY.md** → Documentació completa de seguretat
- **USAGE_EXAMPLES.md** → Exemples amb curl
- **backend/README.md** → Documentació de l'API
- **Dev UI** → http://localhost:8080/q/dev

## 🎉 Començar Ara!

1. ✅ Importa el fitxer JSON
2. ✅ Configura les variables d'entorn
3. ✅ Executa Login Phase 1 i Phase 2
4. ✅ Comença a explorar l'API!

Gaudeix provant Minerva! 🚀
