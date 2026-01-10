# MongoDB Setup per Windows

## Opció 1: Docker (Recomanat) 🐳

### Si tens Docker Desktop instal·lat:

```powershell
# Parar i eliminar contenidor anterior (si existeix)
docker stop minerva-mongo 2>$null
docker rm minerva-mongo 2>$null

# Crear nou contenidor sense autenticació (per desenvolupament local)
docker run -d `
  --name minerva-mongo `
  -p 27017:27017 `
  mongo:7.0
```

### Verificar que funciona:

```powershell
# Veure logs
docker logs minerva-mongo

# Comprovar que està executant-se
docker ps | Select-String minerva-mongo
```

## Opció 2: Instal·lació Local de MongoDB

### Descarregar i Instal·lar:

1. Ves a: https://www.mongodb.com/try/download/community
2. Selecciona:
   - Version: 7.0.x (latest)
   - Platform: Windows
   - Package: MSI
3. Descarrega i executa l'instal·lador
4. Durant la instal·lació:
   - Selecciona "Complete"
   - Marca "Install MongoDB as a Service"
   - **NO** marquis "Install MongoDB Compass" (opcional)

### Verificar la Instal·lació:

```powershell
# Comprovar que el servei està executant-se
Get-Service MongoDB

# Hauria de mostrar:
# Status   Name               DisplayName
# ------   ----               -----------
# Running  MongoDB            MongoDB
```

### Connectar-se a MongoDB:

```powershell
# Obrir shell de MongoDB
mongosh
```

Hauries de veure:
```
Current Mongosh Log ID: ...
Connecting to: mongodb://127.0.0.1:27017/
Using MongoDB: 7.0.x
```

## Opció 3: MongoDB amb Autenticació (Producció)

Si vols usar autenticació (més segur, però més complex):

### Amb Docker:

```powershell
docker run -d `
  --name minerva-mongo `
  -p 27017:27017 `
  -e MONGO_INITDB_ROOT_USERNAME=admin `
  -e MONGO_INITDB_ROOT_PASSWORD=securepassword `
  mongo:7.0
```

Després, **descomenta** les línies d'autenticació a `application.properties`:

```properties
quarkus.mongodb.credentials.username=${MONGODB_USER:admin}
quarkus.mongodb.credentials.password=${MONGODB_PASSWORD:securepassword}
quarkus.mongodb.credentials.auth-source=admin
```

## Verificar Connexió des de Quarkus

Un cop MongoDB estigui executant-se:

1. **Reinicia Quarkus** (si estava executant-se):
   ```powershell
   # Al terminal on està quarkus:dev, prem: Ctrl+C
   # Després torna a executar:
   .\mvnw.cmd quarkus:dev
   ```

2. **Comprova el Health Check**:
   - Obre el navegador: http://localhost:8080/health
   - Hauries de veure:
     ```json
     {
       "status": "UP",
       "checks": [
         {
           "name": "MongoDB connection health check",
           "status": "UP"
         }
       ]
     }
     ```

## Troubleshooting

### Error: "Cannot connect to MongoDB"

```powershell
# Comprovar si MongoDB està executant-se
docker ps | Select-String mongo
# O si és instal·lació local:
Get-Service MongoDB
```

### Error: "Authentication failed"

- Assegura't que les credencials a `application.properties` coincideixin amb les de MongoDB
- Per desenvolupament local, és més fàcil usar MongoDB sense autenticació (Opció 1)

### Error: "Port 27017 already in use"

```powershell
# Veure què està usant el port
netstat -ano | findstr :27017

# Matar el procés (substitueix <PID> pel número que veus)
taskkill /PID <PID> /F
```

## Crear Usuari Admin Inicial

Un cop MongoDB funcioni i Quarkus s'hagi iniciat, necessitaràs crear el primer usuari admin.

Segueix les instruccions a `FIRST_ADMIN_SETUP.md` (si existeix) o consulta amb l'assistent.

---

**Recomanació**: Per desenvolupament local a Windows, usa **Opció 1 (Docker sense autenticació)**. És el més senzill i ràpid.
