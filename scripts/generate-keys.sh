#!/bin/bash

# Script per generar claus JWT RSA per Minerva
# Ús: ./scripts/generate-keys.sh

set -e

echo "=== Minerva - Generador de Claus JWT ==="
echo ""

# Determinar directori de destinació
if [ -d "backend/src/main/resources" ]; then
    KEY_DIR="backend/src/main/resources/keys"
else
    KEY_DIR="keys"
fi

# Crear directori si no existeix
mkdir -p "$KEY_DIR"

# Comprovar si ja existeixen claus
if [ -f "$KEY_DIR/private-key.pem" ] || [ -f "$KEY_DIR/public-key.pem" ]; then
    echo "⚠️  ALERTA: Ja existeixen claus al directori $KEY_DIR"
    read -p "Vols sobrescriure-les? (s/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        echo "Operació cancel·lada."
        exit 0
    fi

    # Backup de claus antigues
    if [ -f "$KEY_DIR/private-key.pem" ]; then
        BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
        echo "Creant backup de claus antigues..."
        mv "$KEY_DIR/private-key.pem" "$KEY_DIR/private-key.pem.backup.$BACKUP_DATE"
        mv "$KEY_DIR/public-key.pem" "$KEY_DIR/public-key.pem.backup.$BACKUP_DATE"
        echo "✓ Backup creat: *.backup.$BACKUP_DATE"
    fi
fi

echo "Generant claus RSA..."
echo ""

# Generar clau privada (2048 bits per desenvolupament, 4096 per producció)
KEY_SIZE=2048
if [ "$1" == "production" ]; then
    KEY_SIZE=4096
    echo "Mode: PRODUCCIÓ (4096 bits)"
else
    echo "Mode: DESENVOLUPAMENT (2048 bits)"
    echo "Consell: Utilitza './generate-keys.sh production' per producció"
fi
echo ""

# Generar clau privada
openssl genrsa -out "$KEY_DIR/private-key.pem" $KEY_SIZE
echo "✓ Clau privada generada: $KEY_DIR/private-key.pem"

# Generar clau pública
openssl rsa -in "$KEY_DIR/private-key.pem" -pubout -out "$KEY_DIR/public-key.pem"
echo "✓ Clau pública generada: $KEY_DIR/public-key.pem"

# Establir permisos segurs
chmod 600 "$KEY_DIR/private-key.pem"
chmod 644 "$KEY_DIR/public-key.pem"
echo "✓ Permisos configurats"

echo ""
echo "=== Claus generades correctament ==="
echo ""
echo "⚠️  IMPORTANT:"
echo "1. La clau privada NO s'ha de compartir MAI"
echo "2. NO pujar aquestes claus a control de versions (Git)"
echo "3. Guardar còpia segura de la clau privada"
echo "4. En producció, usar claus de 4096 bits"
echo ""
echo "Ubicació de les claus:"
echo "  Privada: $KEY_DIR/private-key.pem"
echo "  Pública: $KEY_DIR/public-key.pem"
echo ""
