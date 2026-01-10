package cat.minerva.model;

import io.quarkus.mongodb.panache.PanacheMongoEntity;
import io.quarkus.mongodb.panache.common.MongoEntity;
import org.bson.types.ObjectId;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * Model d'usuari per al sistema Minerva.
 *
 * Seguretat implementada:
 * - Contrasenya hashejada amb Argon2id (mai es guarda en text pla)
 * - Salt únic per cada usuari (generat automàticament per Argon2)
 * - 2FA obligatori (TOTP o U2F/FIDO2)
 * - Bloqueig de compte després de múltiples intents fallits
 * - Tracking de l'últim accés per detectar inactivitat
 *
 * El model està dissenyat per ser immutable en els camps crítics
 * i totes les modificacions queden registrades en els logs d'auditoria.
 */
@MongoEntity(collection = "users")
public class User extends PanacheMongoEntity {

    /**
     * Nom d'usuari únic (utilitzat per fer login).
     * No es pot canviar després de la creació per raons de seguretat i auditoria.
     */
    public String username;

    /**
     * Hash de la contrasenya generat amb Argon2id.
     * Inclou automàticament el salt dins del hash.
     * Format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
     *
     * IMPORTANT: Mai es guarda la contrasenya en text pla.
     */
    public String passwordHash;

    /**
     * Rols assignats a l'usuari (RBAC).
     * Un usuari pot tenir múltiples rols per permetre flexibilitat.
     * Per defecte: CONTRIBUIDOR (mínim privilegi).
     */
    public Set<UserRole> roles = new HashSet<>();

    /**
     * Indica si el compte està actiu.
     * Un compte desactivat no pot fer login.
     */
    public boolean active = true;

    /**
     * Secret TOTP per a 2FA (Base32 encoded).
     * S'utilitza per generar codis temporals de 6 dígits cada 30 segons (RFC 6238).
     * Aquest secret mai es mostra a l'usuari després de la configuració inicial.
     */
    public String totpSecret;

    /**
     * Indica si el 2FA està configurat i activat.
     * El login no és complet fins que el 2FA és validat.
     */
    public boolean twoFactorEnabled = false;

    /**
     * Clau pública U2F/FIDO2 per autenticació amb clau física (opcional).
     * Permet autenticació més segura amb dispositius hardware.
     */
    public String u2fPublicKey;

    /**
     * Comptador d'intents de login fallits.
     * Utilitzat per implementar bloqueig de compte després de múltiples intents.
     */
    public int failedLoginAttempts = 0;

    /**
     * Timestamp de quan el compte es va bloquejar (si aplica).
     * Null si el compte no està bloquejat.
     */
    public Instant lockedUntil;

    /**
     * Data i hora de creació del compte.
     * Immutable després de la creació.
     */
    public Instant createdAt;

    /**
     * Data i hora de l'última modificació del compte.
     * S'actualitza en canvis de contrasenya, rols, etc.
     */
    public Instant updatedAt;

    /**
     * Data i hora de l'últim login exitós.
     * Utilitzat per detectar comptes inactius i possibles anomalies.
     */
    public Instant lastLoginAt;

    /**
     * IP de l'últim login exitós.
     * Utilitzat per detectar accessos des de localitzacions inusuals.
     */
    public String lastLoginIp;

    /**
     * Fingerprint del dispositiu de l'últim login.
     * Hash del user-agent per detectar canvis de dispositiu.
     */
    public String lastDeviceFingerprint;

    /**
     * Data i hora de l'últim canvi de contrasenya.
     * Permet forçar canvis periòdics de contrasenya si és necessari.
     */
    public Instant lastPasswordChangeAt;

    /**
     * Email de l'usuari (opcional).
     * Pot utilitzar-se per notificacions de seguretat.
     */
    public String email;

    /**
     * Nom complet de l'usuari (opcional).
     * Per identificació humana, no utilitzat per autenticació.
     */
    public String fullName;

    /**
     * Comprovació si el compte està bloquejat actualment.
     *
     * @return true si el compte està bloquejat, false altrament
     */
    public boolean isLocked() {
        if (lockedUntil == null) {
            return false;
        }
        // Si el temps de bloqueig ha expirat, desbloquegem automàticament
        if (Instant.now().isAfter(lockedUntil)) {
            lockedUntil = null;
            failedLoginAttempts = 0;
            return false;
        }
        return true;
    }

    /**
     * Bloqueig del compte per un període determinat.
     *
     * @param durationSeconds duració del bloqueig en segons
     */
    public void lockAccount(long durationSeconds) {
        this.lockedUntil = Instant.now().plusSeconds(durationSeconds);
    }

    /**
     * Desbloqueja el compte i reinicia el comptador d'intents fallits.
     */
    public void unlockAccount() {
        this.lockedUntil = null;
        this.failedLoginAttempts = 0;
    }

    /**
     * Incrementa el comptador d'intents de login fallits.
     */
    public void incrementFailedAttempts() {
        this.failedLoginAttempts++;
    }

    /**
     * Reinicia el comptador d'intents de login fallits.
     * Es crida després d'un login exitós.
     */
    public void resetFailedAttempts() {
        this.failedLoginAttempts = 0;
    }

    /**
     * Comprova si l'usuari té un rol específic.
     *
     * @param role rol a comprovar
     * @return true si l'usuari té el rol, false altrament
     */
    public boolean hasRole(UserRole role) {
        return roles.contains(role);
    }

    /**
     * Comprova si l'usuari és administrador.
     *
     * @return true si l'usuari és ADMIN
     */
    public boolean isAdmin() {
        return hasRole(UserRole.ADMIN);
    }
}
