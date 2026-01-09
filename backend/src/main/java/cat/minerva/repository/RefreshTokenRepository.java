package cat.minerva.repository;

import cat.minerva.model.RefreshToken;
import io.quarkus.mongodb.panache.PanacheMongoRepository;
import jakarta.enterprise.context.ApplicationScoped;
import org.bson.types.ObjectId;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repositori per gestionar refresh tokens a MongoDB.
 *
 * Proporciona mètodes per crear, trobar, rotar i revocar tokens
 * amb alta seguretat.
 */
@ApplicationScoped
public class RefreshTokenRepository implements PanacheMongoRepository<RefreshToken> {

    /**
     * Troba un refresh token pel seu hash.
     *
     * @param tokenHash hash del token (SHA-256)
     * @return Optional amb el token si existeix
     */
    public Optional<RefreshToken> findByTokenHash(String tokenHash) {
        return find("tokenHash", tokenHash).firstResultOptional();
    }

    /**
     * Troba tots els tokens vàlids d'un usuari.
     *
     * @param userId ID de l'usuari
     * @return llista de tokens vàlids
     */
    public List<RefreshToken> findValidByUserId(ObjectId userId) {
        return list("userId = ?1 and revoked = false and expiresAt > ?2",
                    userId, Instant.now());
    }

    /**
     * Troba tots els tokens d'un usuari (inclosos revocats i expirats).
     *
     * @param userId ID de l'usuari
     * @return llista de tots els tokens
     */
    public List<RefreshToken> findAllByUserId(ObjectId userId) {
        return list("userId", userId);
    }

    /**
     * Troba tokens per dispositiu específic.
     *
     * @param userId ID de l'usuari
     * @param deviceFingerprint fingerprint del dispositiu
     * @return llista de tokens del dispositiu
     */
    public List<RefreshToken> findByUserIdAndDevice(ObjectId userId, String deviceFingerprint) {
        return list("userId = ?1 and deviceFingerprint = ?2 and revoked = false and expiresAt > ?3",
                    userId, deviceFingerprint, Instant.now());
    }

    /**
     * Revoca tots els tokens d'un usuari.
     * Utilitzat en logout global o compromís de compte.
     *
     * @param userId ID de l'usuari
     * @param reason raó de la revocació
     * @return nombre de tokens revocats
     */
    public long revokeAllForUser(ObjectId userId, String reason) {
        List<RefreshToken> tokens = findValidByUserId(userId);
        tokens.forEach(token -> token.revoke(reason));
        tokens.forEach(this::update);
        return tokens.size();
    }

    /**
     * Elimina tokens expirats de la base de dades.
     * Hauria d'executar-se periòdicament per netejar la BD.
     *
     * @return nombre de tokens eliminats
     */
    public long deleteExpired() {
        return delete("expiresAt < ?1", Instant.now());
    }

    /**
     * Troba tokens potencialment compromesos (reutilitzats).
     *
     * @return llista de tokens sospitosos
     */
    public List<RefreshToken> findCompromised() {
        return list("useCount > 1 and revoked = false");
    }

    /**
     * Troba tokens que no s'han utilitzat durant molt temps.
     *
     * @param days nombre de dies d'inactivitat
     * @return llista de tokens inactius
     */
    public List<RefreshToken> findInactive(int days) {
        Instant threshold = Instant.now().minus(days, java.time.temporal.ChronoUnit.DAYS);
        return list("lastUsedAt < ?1 and revoked = false", threshold);
    }
}
