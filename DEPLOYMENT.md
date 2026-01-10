# Minerva - Guia de Desplegament

## Índex

1. [Requisits](#requisits)
2. [Desplegament en Desenvolupament](#desplegament-en-desenvolupament)
3. [Desplegament en Producció](#desplegament-en-producció)
4. [Configuració de Seguretat](#configuració-de-seguretat)
5. [Backup i Recuperació](#backup-i-recuperació)
6. [Monitorització](#monitorització)

---

## Requisits

### Desenvolupament

- Java 17 o superior
- Maven 3.8+
- Node.js 18+ i npm
- MongoDB 7.0+
- Docker i Docker Compose (opcional)

### Producció

- Java 17 o superior
- MongoDB 7.0+ amb autenticació i TLS
- Nginx o Apache (reverse proxy)
- Certificat SSL/TLS vàlid
- Mínim 4GB RAM, 2 CPU cores
- Disc: 20GB + espai per logs

---

## Desplegament en Desenvolupament

### Opció 1: Docker Compose (Recomanat)

```bash
# 1. Clonar repositori
git clone https://github.com/botvhs/minerva.git
cd minerva

# 2. Copiar variables d'entorn
cp .env.example .env

# 3. Editar .env amb les teves credencials
nano .env

# 4. Generar claus JWT
./scripts/generate-keys.sh

# 5. Executar tot amb Docker Compose
docker-compose up -d

# 6. Verificar que tot funciona
docker-compose ps
docker-compose logs -f backend
```

Aplicació disponible a:
- Backend: http://localhost:8080
- Frontend: http://localhost:4200
- Mongo Express: http://localhost:8081 (user: admin)

### Opció 2: Manual

#### Backend

```bash
# 1. Configurar MongoDB
docker run -d \
  --name minerva-mongo \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=securepass \
  mongo:7.0

# 2. Executar script de setup
docker exec -i minerva-mongo mongosh < mongodb-setup.js

# 3. Generar claus JWT
mkdir -p backend/src/main/resources/keys
openssl genrsa -out backend/src/main/resources/keys/private-key.pem 2048
openssl rsa \
  -in backend/src/main/resources/keys/private-key.pem \
  -pubout \
  -out backend/src/main/resources/keys/public-key.pem

# 4. Executar backend
cd backend
./mvnw quarkus:dev
```

#### Frontend

```bash
cd frontend
npm install
npm start
```

---

## Desplegament en Producció

### 1. Preparació del Servidor

```bash
# Actualitzar sistema
sudo apt update && sudo apt upgrade -y

# Instal·lar Java 17
sudo apt install openjdk-17-jdk -y

# Instal·lar MongoDB
wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update
sudo apt install -y mongodb-org

# Instal·lar Nginx
sudo apt install nginx -y
```

### 2. Configurar MongoDB amb Seguretat

```bash
# Habilitar autenticació
sudo nano /etc/mongod.conf
```

Afegir:
```yaml
security:
  authorization: enabled

net:
  bindIp: 127.0.0.1
  port: 27017
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongodb/mongodb.pem
    CAFile: /etc/ssl/mongodb/ca.pem
```

```bash
# Reiniciar MongoDB
sudo systemctl restart mongod

# Crear usuari de l'aplicació
mongosh admin -u admin -p

# A la consola de MongoDB:
use minerva_db
db.createUser({
  user: "minerva_app",
  pwd: passwordPrompt(),
  roles: [{ role: "readWrite", db: "minerva_db" }]
})
```

### 3. Generar Claus de Producció

```bash
# Directori segur per claus
sudo mkdir -p /opt/minerva/keys
sudo chmod 700 /opt/minerva/keys

# Generar claus RSA
sudo openssl genrsa -out /opt/minerva/keys/private-key.pem 4096
sudo openssl rsa \
  -in /opt/minerva/keys/private-key.pem \
  -pubout \
  -out /opt/minerva/keys/public-key.pem

# Permisos restrictius
sudo chmod 600 /opt/minerva/keys/private-key.pem
sudo chmod 644 /opt/minerva/keys/public-key.pem
sudo chown minerva:minerva /opt/minerva/keys/*
```

### 4. Compilar Backend

```bash
cd backend

# Compilar en mode producció
./mvnw clean package -Dquarkus.package.type=uber-jar

# Copiar JAR al servidor
sudo mkdir -p /opt/minerva/backend
sudo cp target/minerva-backend-1.0.0-runner.jar /opt/minerva/backend/
```

### 5. Crear Servei Systemd

```bash
sudo nano /etc/systemd/system/minerva-backend.service
```

Contingut:
```ini
[Unit]
Description=Minerva Security Backend
After=network.target mongodb.service

[Service]
Type=simple
User=minerva
Group=minerva
WorkingDirectory=/opt/minerva/backend
ExecStart=/usr/bin/java \
  -Dquarkus.http.port=8080 \
  -Dquarkus.mongodb.connection-string=mongodb://minerva_app:PASSWORD@localhost:27017 \
  -Dquarkus.mongodb.database=minerva_db \
  -Dmp.jwt.verify.publickey.location=/opt/minerva/keys/public-key.pem \
  -Dsmallerye.jwt.sign.key.location=/opt/minerva/keys/private-key.pem \
  -jar minerva-backend-1.0.0-runner.jar

Restart=always
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/minerva

[Install]
WantedBy=multi-user.target
```

```bash
# Habilitar i iniciar servei
sudo systemctl daemon-reload
sudo systemctl enable minerva-backend
sudo systemctl start minerva-backend
sudo systemctl status minerva-backend
```

### 6. Configurar Nginx com a Reverse Proxy

```bash
sudo nano /etc/nginx/sites-available/minerva
```

Contingut:
```nginx
# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name minerva;
    return 301 https://$server_name$request_uri;
}

# HTTPS
server {
    listen 443 ssl http2;
    server_name minerva;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/minerva.crt;
    ssl_certificate_key /etc/ssl/private/minerva.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" always;

    # Proxy to Backend
    location /api/ {
        proxy_pass http://localhost:8080/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Frontend
    location / {
        root /var/www/minerva/frontend;
        try_files $uri $uri/ /index.html;
    }

    # Logs
    access_log /var/log/nginx/minerva-access.log;
    error_log /var/log/nginx/minerva-error.log;
}
```

```bash
# Activar configuració
sudo ln -s /etc/nginx/sites-available/minerva /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 7. Compilar i Desplegar Frontend

```bash
cd frontend

# Compilar per producció
npm run build --prod

# Copiar a directori web
sudo mkdir -p /var/www/minerva/frontend
sudo cp -r dist/minerva/* /var/www/minerva/frontend/
sudo chown -R www-data:www-data /var/www/minerva
```

### 8. Configurar Firewall

```bash
# Només permetre HTTPS i SSH
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# MongoDB només localhost
sudo ufw deny 27017
```

---

## Configuració de Seguretat

### Variables d'Entorn de Producció

```bash
sudo nano /etc/environment
```

Afegir:
```bash
MONGODB_USER=minerva_app
MONGODB_PASSWORD=<password_fort>
JWT_ISSUER=https://min3rva.cat
QUARKUS_PROFILE=prod
```

### Rotació de Claus JWT

Cada 90 dies:
```bash
# 1. Generar noves claus
sudo openssl genrsa -out /opt/minerva/keys/private-key-new.pem 4096
sudo openssl rsa \
  -in /opt/minerva/keys/private-key-new.pem \
  -pubout \
  -out /opt/minerva/keys/public-key-new.pem

# 2. Actualitzar referències
sudo mv /opt/minerva/keys/private-key.pem /opt/minerva/keys/private-key-old.pem
sudo mv /opt/minerva/keys/private-key-new.pem /opt/minerva/keys/private-key.pem
sudo mv /opt/minerva/keys/public-key.pem /opt/minerva/keys/public-key-old.pem
sudo mv /opt/minerva/keys/public-key-new.pem /opt/minerva/keys/public-key.pem

# 3. Reiniciar servei
sudo systemctl restart minerva-backend

# 4. Eliminar claus velles després de verificar
sudo rm /opt/minerva/keys/*-old.pem
```

---

## Backup i Recuperació

### Backup Automàtic de MongoDB

```bash
sudo nano /opt/minerva/scripts/backup.sh
```

Contingut:
```bash
#!/bin/bash

BACKUP_DIR="/opt/minerva/backups/mongodb"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="minerva_backup_$DATE"

# Crear backup
mongodump \
  --uri="mongodb://minerva_app:PASSWORD@localhost:27017/minerva_db" \
  --out="$BACKUP_DIR/$BACKUP_NAME" \
  --gzip

# Eliminar backups més antics de 30 dies
find $BACKUP_DIR -type d -mtime +30 -exec rm -rf {} \;

echo "Backup completat: $BACKUP_NAME"
```

```bash
# Permetre execució
sudo chmod +x /opt/minerva/scripts/backup.sh

# Afegir a crontab (cada dia a les 2 AM)
sudo crontab -e
```

Afegir:
```
0 2 * * * /opt/minerva/scripts/backup.sh >> /var/log/minerva/backup.log 2>&1
```

### Recuperació

```bash
# Restaurar backup
mongorestore \
  --uri="mongodb://minerva_app:PASSWORD@localhost:27017/minerva_db" \
  --gzip \
  /opt/minerva/backups/mongodb/minerva_backup_YYYYMMDD_HHMMSS
```

---

## Monitorització

### Logs

```bash
# Backend logs
sudo journalctl -u minerva-backend -f

# Nginx logs
sudo tail -f /var/log/nginx/minerva-access.log
sudo tail -f /var/log/nginx/minerva-error.log

# MongoDB logs
sudo tail -f /var/log/mongodb/mongod.log
```

### Health Checks

```bash
# Backend health
curl https://min3rva.cat/api/health

# MongoDB status
mongosh minerva_db -u minerva_app -p --eval "db.serverStatus()"
```

### Alertes

Configurar alertes per:
- Intents de login fallits > 100/hora
- Comptes bloquejats
- Errors del backend
- Disc > 80% ple
- RAM > 90% usada

---

## Checklist de Producció

- [ ] MongoDB amb autenticació i TLS
- [ ] Claus JWT generades i segures
- [ ] HTTPS configurat amb certificat vàlid
- [ ] Firewall configurat (només 443 i 22)
- [ ] Variables d'entorn de producció
- [ ] Backups automàtics configurats
- [ ] Logs configurats i rotació activada
- [ ] Health checks funcionant
- [ ] Monitorització i alertes actives
- [ ] Usuari admin creat i contrasenya canviada
- [ ] Documentació actualitzada
- [ ] Tests de penetració completats

---

## Suport

Per problemes de desplegament, consulta:
- [SECURITY.md](SECURITY.md)
- [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md)
- Logs del sistema

En cas d'emergència de seguretat, contacta immediatament amb l'equip de seguretat.
