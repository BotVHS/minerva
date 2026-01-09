package cat.minerva.security;

import cat.minerva.model.RefreshToken;
import cat.minerva.model.User;
import cat.minerva.repository.RefreshTokenRepository;
import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * Servei per gestionar JWT tokens (access i refresh).
 *
 * Sistema de tokens de dues capes:
 *
 * 1. ACCESS TOKEN (JWT):
 *    - Vida molt curta (5-10 minuts)
 *    - Conté claims: userId, username, roles
 *    - Signat amb RS256 (clau privada)
 *    - Verificat amb clau pública
 *    - No es pot revocar (per això és de vida curta)
 *
 * 2. REFRESH TOKEN:
 *    - Vida més llarga (24 hores)
 *    - Emmagatzemat xifrat (SHA-256) a MongoDB
 *    - Vinculat a dispositiu (fingerprint)
 *    - Rotació automàtica: cada ús genera un nou token
 *    - Pot revocar-se immediatament
 *    - Detecta reutilització (possible atac)
 *
 * Flux de seguretat:
 * 1. Login → Access Token + Refresh Token
 * 2. Cada request usa l'Access Token
 * 3. Quan expira, usar Refresh Token per obtenir nou Access Token
 * 4. Rotació: nou Refresh Token, invalidar l'anterior
 * 5. Logout: revocar Refresh Token
 */
@ApplicationScoped
public class TokenService {

    private static final Logger LOG = Logger.getLogger(TokenService.class);

    @ConfigProperty(name = "minerva.security.access-token.duration", defaultValue = "300")
    long accessTokenDuration; // segons (5 minuts per defecte)

    @ConfigProperty(name = "minerva.security.refresh-token.duration", defaultValue = "86400")
    long refreshTokenDuration; // segons (24 hores per defecte)

    @Inject
    RefreshTokenRepository refreshTokenRepository;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Genera un Access Token (JWT) per un usuari.
     *
     * El token conté:
     * - sub: userId
     * - upn: username (User Principal Name)
     * - groups: rols de l'usuari
     * - iat: issued at
     * - exp: expiration
     *
     * @param user usuari
     * @return JWT signat
     */
    public String generateAccessToken(User user) {
        Set<String> roles = new HashSet<>();
        user.roles.forEach(role -> roles.add(role.name()));

        String token = Jwt.issuer("https://minerva.gov")
            .upn(user.username)
            .subject(user.id.toString())
            .groups(roles)
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(accessTokenDuration))
            .sign();

        LOG.debugf("Generated access token for user: %s (expires in %d seconds)",
                  user.username, accessTokenDuration);

        return token;
    }

    /**
     * Genera un Refresh Token per un usuari i dispositiu.
     *
     * El token és un string aleatori de 256 bits (Base64).
     * S'emmagatzema només el hash (SHA-256) a la base de dades.
     *
     * @param user usuari
     * @param deviceFingerprint fingerprint del dispositiu
     * @param ipAddress IP del client
     * @return token en text pla (només es mostra una vegada)
     */
    @Transactional
    public String generateRefreshToken(User user, String deviceFingerprint, String ipAddress) {
        // Generar token aleatori (256 bits)
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

        // Calcular hash del token per emmagatzemar
        String tokenHash = hashToken(token);

        // Crear RefreshToken
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.userId = user.id;
        refreshToken.tokenHash = tokenHash;
        refreshToken.deviceFingerprint = deviceFingerprint;
        refreshToken.ipAddress = ipAddress;
        refreshToken.createdAt = Instant.now();
        refreshToken.expiresAt = Instant.now().plusSeconds(refreshTokenDuration);
        refreshToken.lastUsedAt = Instant.now();

        refreshTokenRepository.persist(refreshToken);

        LOG.debugf("Generated refresh token for user: %s (expires in %d seconds)",
                  user.username, refreshTokenDuration);

        return token;
    }

    /**
     * Valida i rota un Refresh Token.
     *
     * Comprovacions de seguretat:
     * 1. El token existeix i el hash coincideix
     * 2. No ha estat revocat
     * 3. No ha expirat
     * 4. El fingerprint del dispositiu coincideix
     * 5. No ha estat reutilitzat (protecció contra atacs)
     *
     * Si és vàlid:
     * - Invalida el token actual
     * - Genera un nou Refresh Token (rotació)
     * - Retorna nou Access Token + nou Refresh Token
     *
     * @param token refresh token en text pla
     * @param deviceFingerprint fingerprint del dispositiu
     * @param ipAddress IP del client
     * @return nou parell de tokens, o null si no és vàlid
     */
    @Transactional
    public TokenPair refreshTokens(String token, String deviceFingerprint, String ipAddress) {
        String tokenHash = hashToken(token);

        var optionalRefreshToken = refreshTokenRepository.findByTokenHash(tokenHash);
        if (optionalRefreshToken.isEmpty()) {
            LOG.warn("Refresh token not found");
            return null;
        }

        RefreshToken refreshToken = optionalRefreshToken.get();

        // Comprovació 1: Token vàlid (no revocat ni expirat)
        if (!refreshToken.isValid()) {
            LOG.warnf("Refresh token invalid: revoked=%s, expired=%s",
                     refreshToken.revoked, Instant.now().isAfter(refreshToken.expiresAt));
            return null;
        }

        // Comprovació 2: Fingerprint del dispositiu
        if (!refreshToken.matchesDevice(deviceFingerprint)) {
            LOG.warnf("Device fingerprint mismatch: expected=%s, got=%s",
                     refreshToken.deviceFingerprint, deviceFingerprint);
            // Possible robatori de token
            refreshToken.revoke("Device fingerprint mismatch");
            refreshTokenRepository.update(refreshToken);
            return null;
        }

        // Comprovació 3: Detecció de reutilització
        if (refreshToken.isPotentiallyCompromised()) {
            LOG.errorf("Token reuse detected! Possible attack. Token ID: %s", refreshToken.id);
            // Revocar tots els tokens de l'usuari per seguretat
            refreshTokenRepository.revokeAllForUser(refreshToken.userId,
                "Token reuse detected - possible attack");
            return null;
        }

        // Marcar com utilitzat
        refreshToken.markAsUsed();

        // Obtenir l'usuari
        User user = User.findById(refreshToken.userId);
        if (user == null || !user.active) {
            LOG.warnf("User not found or inactive: %s", refreshToken.userId);
            refreshToken.revoke("User not found or inactive");
            refreshTokenRepository.update(refreshToken);
            return null;
        }

        // Revocar el token actual (rotació)
        refreshToken.revoke("Rotated");
        refreshTokenRepository.update(refreshToken);

        // Generar nous tokens
        String newAccessToken = generateAccessToken(user);
        String newRefreshToken = generateRefreshToken(user, deviceFingerprint, ipAddress);

        // Vincular el nou token a l'anterior (cadena de rotació)
        var newRefreshTokenEntity = refreshTokenRepository.findByTokenHash(hashToken(newRefreshToken));
        newRefreshTokenEntity.ifPresent(rt -> {
            rt.previousTokenId = refreshToken.id;
            refreshTokenRepository.update(rt);
        });

        LOG.debugf("Tokens refreshed successfully for user: %s", user.username);

        return new TokenPair(newAccessToken, newRefreshToken);
    }

    /**
     * Revoca un Refresh Token (logout).
     *
     * @param token refresh token a revocar
     * @param reason raó de la revocació
     * @return true si s'ha revocat, false si no existeix
     */
    @Transactional
    public boolean revokeRefreshToken(String token, String reason) {
        String tokenHash = hashToken(token);

        var optionalRefreshToken = refreshTokenRepository.findByTokenHash(tokenHash);
        if (optionalRefreshToken.isEmpty()) {
            LOG.debug("Token not found for revocation");
            return false;
        }

        RefreshToken refreshToken = optionalRefreshToken.get();
        refreshToken.revoke(reason);
        refreshTokenRepository.update(refreshToken);

        LOG.debugf("Refresh token revoked: %s", reason);
        return true;
    }

    /**
     * Revoca tots els tokens d'un usuari (logout global).
     *
     * @param user usuari
     * @param reason raó de la revocació
     * @return nombre de tokens revocats
     */
    @Transactional
    public long revokeAllUserTokens(User user, String reason) {
        long count = refreshTokenRepository.revokeAllForUser(user.id, reason);
        LOG.infof("Revoked %d tokens for user: %s", count, user.username);
        return count;
    }

    /**
     * Calcula el hash SHA-256 d'un token.
     *
     * Mai emmagatzemem tokens en text pla.
     *
     * @param token token en text pla
     * @return hash hexadecimal
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();

        } catch (Exception e) {
            LOG.error("Error hashing token", e);
            throw new RuntimeException("Failed to hash token", e);
        }
    }

    /**
     * Neteja tokens expirats de la base de dades.
     * Hauria d'executar-se periòdicament (ex: cada dia).
     *
     * @return nombre de tokens eliminats
     */
    @Transactional
    public long cleanupExpiredTokens() {
        long deleted = refreshTokenRepository.deleteExpired();
        LOG.infof("Cleaned up %d expired refresh tokens", deleted);
        return deleted;
    }

    /**
     * Classe per retornar parells de tokens.
     */
    public static class TokenPair {
        public final String accessToken;
        public final String refreshToken;

        public TokenPair(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
    }
}
