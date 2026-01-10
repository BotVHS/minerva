package cat.minerva.model;

import io.quarkus.mongodb.panache.PanacheMongoEntity;
import io.quarkus.mongodb.panache.common.MongoEntity;
import org.bson.types.ObjectId;

import java.time.Instant;

/**
 * Model per logs d'auditoria immutables.
 *
 * Sistema de logs tipus blockchain:
 * - Cada entrada conté un hash del contingut + hash de l'entrada anterior
 * - Qualsevol alteració trenca la cadena de hashs i és detectable
 * - Col·lecció append-only (només escriptura, mai modificació/eliminació)
 * - Totes les accions crítiques queden registrades amb context complet
 *
 * Informació registrada:
 * - Què: acció realitzada (login, modificació d'usuari, etc.)
 * - Qui: usuari que va fer l'acció
 * - Quan: timestamp precís
 * - Des d'on: IP i informació del dispositiu
 * - Resultat: èxit o fallida
 * - Context: detalls addicionals rellevants
 *
 * Aquest sistema permet auditories completes i detecció de manipulacions,
 * complint amb els requisits de seguretat.
 */
@MongoEntity(collection = "audit_logs")
public class AuditLog extends PanacheMongoEntity {

    /**
     * Tipus d'acció registrada.
     */
    public AuditAction action;

    /**
     * ID de l'usuari que va realitzar l'acció.
     * Null en accions anònimes (login fallit, etc.).
     */
    public ObjectId userId;

    /**
     * Nom d'usuari (cache per facilitar consultes).
     * No es fa servir per auditoria crítica, només el userId.
     */
    public String username;

    /**
     * Rols de l'usuari en el moment de l'acció.
     * Important per saber quins permisos tenia l'usuari.
     */
    public String userRoles;

    /**
     * Timestamp precís de l'acció.
     * UTC per evitar problemes de zones horàries.
     */
    public Instant timestamp;

    /**
     * IP des de la qual es va realitzar l'acció.
     */
    public String ipAddress;

    /**
     * User-Agent del client (navegador/aplicació).
     */
    public String userAgent;

    /**
     * Fingerprint del dispositiu (hash del user-agent).
     */
    public String deviceFingerprint;

    /**
     * Indica si l'acció va tenir èxit o va fallar.
     */
    public boolean success;

    /**
     * Detalls addicionals de l'acció.
     * Informació contextual rellevant (ex: "Rol ADMIN assignat a usuari X").
     */
    public String details;

    /**
     * Missatge d'error si l'acció va fallar.
     */
    public String errorMessage;

    /**
     * ID del recurs afectat (usuari modificat, token revocat, etc.).
     * Permet traçabilitat completa.
     */
    public ObjectId targetResourceId;

    /**
     * Tipus del recurs afectat (USER, TOKEN, etc.).
     */
    public String targetResourceType;

    /**
     * Hash de l'entrada anterior en la cadena.
     * Aquest és el mecanisme tipus blockchain que garanteix immutabilitat.
     *
     * El hash és: SHA-256(previousHash + contingut_actual)
     * Si algú modifica una entrada antiga, tots els hashs posteriors seran invàlids.
     */
    public String previousHash;

    /**
     * Hash d'aquesta entrada.
     * Calculat com: SHA-256(previousHash + timestamp + action + userId + ... tots els camps)
     *
     * Aquest hash es converteix en el previousHash de la següent entrada.
     */
    public String currentHash;

    /**
     * Número de seqüència en la cadena de logs.
     * Permet detectar entrades eliminades (forats en la seqüència).
     */
    public long sequenceNumber;

    /**
     * Metadades addicionals en format JSON.
     * Per informació extra que no cau en els camps estàndard.
     */
    public String metadata;

    /**
     * Indica si aquest log ha estat verificat.
     * Utilitzat per processos de verificació periòdica de la integritat.
     */
    public boolean verified = false;

    /**
     * Data de l'última verificació d'integritat.
     */
    public Instant lastVerifiedAt;

    /**
     * Comprova si aquesta entrada és vàlida verificant el hash.
     *
     * @param expectedPreviousHash hash esperat de l'entrada anterior
     * @return true si el hash és vàlid, false si hi ha hagut manipulació
     */
    public boolean verifyIntegrity(String expectedPreviousHash) {
        // Comprova que el previousHash coincideix
        if (!this.previousHash.equals(expectedPreviousHash)) {
            return false;
        }

        // Recalcula el hash actual i comprova que coincideix
        String recalculatedHash = calculateHash();
        return this.currentHash.equals(recalculatedHash);
    }

    /**
     * Calcula el hash d'aquesta entrada.
     * Utilitzat per verificar la integritat i crear nous logs.
     *
     * @return hash SHA-256 de l'entrada
     */
    public String calculateHash() {
        // Construcció del string a hashejar amb tots els camps rellevants
        StringBuilder data = new StringBuilder();
        data.append(previousHash != null ? previousHash : "");
        data.append(sequenceNumber);
        data.append(timestamp != null ? timestamp.toString() : "");
        data.append(action != null ? action.toString() : "");
        data.append(userId != null ? userId.toString() : "");
        data.append(username != null ? username : "");
        data.append(ipAddress != null ? ipAddress : "");
        data.append(success);
        data.append(details != null ? details : "");
        data.append(targetResourceId != null ? targetResourceId.toString() : "");

        // Calcular SHA-256
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));

            // Convertir a hex
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }
}
