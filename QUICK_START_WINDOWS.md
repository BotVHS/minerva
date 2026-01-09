# Guia Ràpida per Executar Minerva a Windows

## ✅ Errors Corregits

He arreglat els errors de compilació:
- ✅ Canviada llibreria TOTP per una més compatible
- ✅ Afegit suport per HttpServletRequest
- ✅ Tots els errors de dependències resolts

## 🔄 Actualitzar el Codi

Primer, actualitza el codi al teu Windows:

```powershell
# Anar al directori del projecte
cd A:\Users\alber\OneDrive\Documentos\GitHub\minerva

# Fer pull dels canvis
git pull origin claude/complete-readme-tasks-BHqEj
```

## ▶️ Executar el Backend

Ara ja pots executar el backend sense errors:

```powershell
# Anar al directori backend
cd backend

# Executar (això descarregarà les noves dependències)
.\mvnw.cmd clean quarkus:dev
```

## ⏱️ Primera Execució

La primera vegada trigarà uns minuts perquè:
1. Descarrega Maven (si no el tens)
2. Descarrega totes les dependències del projecte (~200MB)
3. Compila el codi

Sigues pacient! Les següents vegades serà molt més ràpid.

## 📊 Què Veuràs

Quan funcioni correctament, veuràs:

```
__  ____  __  _____   ___  __ ____  ______
 --/ __ \/ / / / _ | / _ \/ //_/ / / / __/
 -/ /_/ / /_/ / __ |/ , _/ ,< / /_/ /\ \
--\___\_\____/_/ |_/_/|_/_/|_|\____/___/

INFO  [io.quarkus] minerva-backend 1.0.0-SNAPSHOT on JVM started in 3.456s
INFO  [io.quarkus] Listening on: http://localhost:8080
```

## 🌐 Verificar que Funciona

Obre el navegador i prova:

1. **Dev UI** (molt útil!): http://localhost:8080/q/dev
2. **Health Check**: http://localhost:8080/health
3. **API Docs**: http://localhost:8080/q/swagger-ui (si està habilitat)

## 🗄️ Sobre MongoDB

Si encara no tens MongoDB:

**Opció Fàcil (Docker):**
```powershell
docker run -d --name minerva-mongo -p 27017:27017 mongo:7.0
```

**Opció Alternativa (Instal·lació Local):**
1. Descarrega: https://www.mongodb.com/try/download/community
2. Instal·la amb el wizard
3. Marca "Install MongoDB as a Service"

MongoDB NO és necessari per compilar el codi, només per executar-lo completament.

## 🎯 Provar l'API

Un cop estigui executant-se, pots provar l'API des de la Dev UI:

1. Ves a http://localhost:8080/q/dev
2. Clica "Endpoints" al menú esquerre
3. Trobaràs tots els endpoints disponibles per provar

## ❌ Si Encara Hi Ha Errors

Si veus errors després del pull:

```powershell
# Netejar completament i recompilar
.\mvnw.cmd clean
.\mvnw.cmd quarkus:dev
```

Si el problema persisteix, copia l'error complet i l'analitzaré.

## 📝 Proper Pas

Un cop funcioni, el següent seria:
1. Crear un usuari admin inicial
2. Provar el login amb 2FA
3. Explorar els endpoints d'administració

Avisa'm quan estigui executant-se! 🚀
