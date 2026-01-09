# minerva

Crea un sistema complet de login ultrasegur amb diferents nivells d'autorització, pensat per a un entorn governamental d’intel·ligència.

BACKEND:
- Framework: **Quarkus (Java)**.
- Base de dades: **MongoDB**.
- No hi ha registre públic; només **administradors poden crear usuaris**.
- Implementa **RBAC (Role-Based Access Control)** amb rols com: ADMIN, ANALISTA, SUPERVISOR, CONTRIBUIDOR.
- Tot el sistema ha d’estar dissenyat per ser **auditable, immutable i resistent a atacs avançats**.

SEGURETAT (OBLIGATÒRIA):
1. **Autenticació**
   - Hashing de contrasenyes amb **Argon2id + salt únic per usuari**.
   - Política de contrasenyes fortes (mínim 12 caràcters, complexitat alta).
   - **2FA obligatori per a tots els usuaris**, amb suport per:
     - TOTP (RFC 6238)
     - Apps com **Authy / Google Authenticator**
     - **U2F / FIDO2** amb clau física
   - El login no és complet fins que el 2FA és validat.

2. **Sessions**
   - **Access tokens de vida molt curta** (5–10 minuts).
   - **Refresh tokens**:
     - Emmagatzemats xifrats a MongoDB.
     - Rotació automàtica en cada ús.
     - Invalidació immediata en logout o comportament sospitós.
   - Vincula els tokens a fingerprint de dispositiu (user-agent + hash).

3. **Autorització**
   - Middleware de seguretat per protegir rutes segons rol.
   - Accés explícit denegat per defecte (deny-by-default).
   - Possibilitat de permisos més fins (RBAC + ABAC opcional).

4. **Logs immutables i auditories**
   - **TOTES les accions han de quedar registrades**:
     - Login (èxit/fallida)
     - Validació 2FA
     - Creació, modificació o desactivació d’usuaris
     - Canvi de rols
     - Accés a recursos sensibles
   - Els logs han de ser **immutables i no modificables**:
     - Escrits en una col·lecció append-only
     - Cada entrada signada criptogràficament (hash encadenat tipus blockchain)
     - Qualsevol alteració ha de ser detectable
   - Incloure timestamps, IP, usuari, rol, acció i resultat.
   - Preparat per auditories de seguretat.

5. **Proteccions addicionals**
   - Rate limiting i detecció de força bruta.
   - Bloqueig de compte després de múltiples intents fallits.
   - Prevenció de NoSQL injection, XSS i CSRF.
   - Headers de seguretat (CSP, HSTS, etc.).

FUNCIONALITATS BACKEND:
- Endpoint de login amb:
  - usuari + contrasenya
  - verificació 2FA
  - retorn d’access token + refresh token
- Endpoint per:
  - Crear usuaris (només admins)
  - Assignar rols
  - Activar/desactivar comptes
  - Canviar contrasenya
- Middleware de seguretat reutilitzable.
- Serveis clarament separats (auth, users, audit).

FRONTEND:
- Framework: **Angular (última versió estable)**.
- Formulari de login en dues fases:
  1. Usuari + contrasenya
  2. Validació 2FA (TOTP o clau física si està configurada)
- Gestió segura dels tokens:
  - Access token en memòria
  - Refresh token amb proteccions adequades
- Panell d’administració:
  - Crear usuaris
  - Assignar rols
  - Forçar reset de 2FA
  - Veure logs d’auditoria (read-only)
- Protecció de rutes segons rol.

ADICIONAL:
- Codi **modular, net i fortament comentat**.
- Pensat per mantenibilitat a llarg termini (10–20 anys).
- Explica breument cada decisió de seguretat i per què s’ha escollit.
- Proporciona:
  1. Estructura de carpetes backend i frontend.
  2. Codi principal funcional (Quarkus + Angular).
  3. Exemple de configuració segura de MongoDB.
  4. Exemple de log immutable amb hash encadenat.
  5. Exemple de flux complet de login amb 2FA i refresh tokens.

Assegura’t que el sistema sigui **extremadament segur, auditable, resistent a manipulacions i adequat per a un projecte d’intel·ligència governamental**.
