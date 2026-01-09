package cat.minerva.model;

import io.quarkus.mongodb.panache.PanacheMongoEntity;
import io.quarkus.mongodb.panache.common.MongoEntity;
import org.bson.types.ObjectId;

import java.time.Instant;

/**
 * Model per gestionar Refresh Tokens amb alta seguretat.
 *
 * Seguretat implementada:
 * - Token emmagatzemat xifrat (només hash a la BD)
 * - Rotació automàtica: cada ús genera un nou token i invalida l'anterior
 * - Vinculació a dispositiu: el token només funciona des del mateix dispositiu
 * - Expiració configurable (24h per defecte)
 * - Invalidació immediata en logout o comportament sospitós
 * - Detecció de reutilització (possible atac)
 *
 * Els refresh tokens permeten obtenir nous access tokens sense reautenticar,
 * però amb múltiples capes de seguretat per prevenir robatori i abús.
 */
@MongoEntity(collection = "refresh_tokens")
public class RefreshToken extends PanacheMongoEntity {

    /**
     * ID de l'usuari propietari del token.
     * Referència a la col·lecció users.
     */
    public ObjectId userId;

    /**
     * Hash del refresh token (SHA-256).
     * Mai guardem el token en text pla a la base de dades.
     * El client rep el token original, nosaltres guardem només el hash.
     */
    public String tokenHash;

    /**
     * Fingerprint del dispositiu (hash del user-agent).
     * El token només funciona des del mateix dispositiu que el va crear.
     * Això prevé robatori de tokens i ús des d'altres dispositius.
     */
    public String deviceFingerprint;

    /**
     * IP des de la qual es va crear el token.
     * Utilitzat per detectar accessos sospitosos.
     */
    public String ipAddress;

    /**
     * Data i hora de creació del token.
     */
    public Instant createdAt;

    /**
     * Data i hora d'expiració del token.
     * Per defecte: 24 hores des de la creació.
     */
    public Instant expiresAt;

    /**
     * Data i hora de l'últim ús del token.
     * Actualitzat cada cop que es fa servir per obtenir un nou access token.
     */
    public Instant lastUsedAt;

    /**
     * Indica si el token ha estat revocat.
     * Un token revocat no es pot utilitzar mai més.
     */
    public boolean revoked = false;

    /**
     * Data i hora de revocació (si aplica).
     */
    public Instant revokedAt;

    /**
     * Raó de la revocació (logout, comportament sospitós, etc.).
     */
    public String revocationReason;

    /**
     * Comptador d'usos del token.
     * En una implementació amb rotació estricta, aquest hauria de ser sempre 0 o 1.
     * Si és > 1, pot indicar un intent de reutilització (atac).
     */
    public int useCount = 0;

    /**
     * ID del token anterior en la cadena de rotació.
     * Permet rastrejar la cadena completa de tokens rotats.
     */
    public ObjectId previousTokenId;

    /**
     * Comprova si el token és vàlid.
     *
     * Un token és vàlid si:
     * - No ha estat revocat
     * - No ha expirat
     *
     * @return true si el token és vàlid, false altrament
     */
    public boolean isValid() {
        if (revoked) {
            return false;
        }
        return Instant.now().isBefore(expiresAt);
    }

    /**
     * Comprova si el fingerprint del dispositiu coincideix.
     *
     * @param fingerprint fingerprint a comprovar
     * @return true si coincideix, false altrament
     */
    public boolean matchesDevice(String fingerprint) {
        return this.deviceFingerprint.equals(fingerprint);
    }

    /**
     * Revoca el token.
     *
     * @param reason raó de la revocació
     */
    public void revoke(String reason) {
        this.revoked = true;
        this.revokedAt = Instant.now();
        this.revocationReason = reason;
    }

    /**
     * Marca el token com utilitzat.
     * Incrementa el comptador d'usos i actualitza lastUsedAt.
     */
    public void markAsUsed() {
        this.useCount++;
        this.lastUsedAt = Instant.now();
    }

    /**
     * Comprova si el token ha estat potencialment reutilitzat (possible atac).
     *
     * @return true si s'ha detectat reutilització sospitosa
     */
    public boolean isPotentiallyCompromised() {
        // Si el token s'ha utilitzat més d'un cop, pot estar compromès
        // En una implementació amb rotació, cada token només s'hauria d'usar 1 cop
        return useCount > 1;
    }
}
