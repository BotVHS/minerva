package cat.minerva.service;

import cat.minerva.audit.AuditService;
import cat.minerva.model.User;
import cat.minerva.repository.UserRepository;
import cat.minerva.security.PasswordHashService;
import cat.minerva.security.TokenService;
import cat.minerva.security.TotpService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.time.Instant;

/**
 * Servei principal d'autenticació.
 *
 * Coordina tot el procés d'autenticació en dues fases:
 * 1. Validació de credencials (usuari + contrasenya)
 * 2. Validació de 2FA (TOTP o U2F)
 *
 * Seguretat implementada:
 * - Hashing de contrasenyes amb Argon2id
 * - 2FA obligatori per tots els usuaris
 * - Bloqueig de compte després de múltiples intents fallits
 * - Rate limiting (controlat pel RateLimitFilter)
 * - Auditoria completa de totes les accions
 * - Vinculació de tokens a dispositiu
 *
 * Flux complet:
 * 1. authenticateCredentials() → valida usuari/contrasenya → SessionToken temporal
 * 2. validate2FA() → valida codi TOTP → Access + Refresh tokens finals
 * 3. refresh() → renova tokens amb Refresh Token
 * 4. logout() → revoca tokens
 */
@ApplicationScoped
public class AuthService {

    private static final Logger LOG = Logger.getLogger(AuthService.class);

    @ConfigProperty(name = "minerva.security.max-failed-attempts", defaultValue = "5")
    int maxFailedAttempts;

    @ConfigProperty(name = "minerva.security.lockout-duration", defaultValue = "1800")
    long lockoutDuration; // segons (30 minuts per defecte)

    @Inject
    UserRepository userRepository;

    @Inject
    PasswordHashService passwordHashService;

    @Inject
    TotpService totpService;

    @Inject
    TokenService tokenService;

    @Inject
    AuditService auditService;

    /**
     * Fase 1: Autentica credencials (usuari + contrasenya).
     *
     * Si les credencials són correctes però el 2FA encara no s'ha validat,
     * retorna un SessionToken temporal que s'utilitza per la fase 2.
     *
     * @param username nom d'usuari
     * @param password contrasenya
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     * @return resultat de l'autenticació (inclou SessionToken si és exitosa)
     */
    public AuthResult authenticateCredentials(String username, String password,
                                             String ipAddress, String userAgent) {
        LOG.debugf("Authentication attempt for user: %s from IP: %s", username, ipAddress);

        // Buscar l'usuari
        var optionalUser = userRepository.findByUsername(username);
        if (optionalUser.isEmpty()) {
            auditService.logLoginFailed(username, "User not found", ipAddress, userAgent);
            return AuthResult.failed("Credencials incorrectes");
        }

        User user = optionalUser.get();

        // Comprovar si el compte està actiu
        if (!user.active) {
            auditService.logLoginFailed(username, "Account disabled", ipAddress, userAgent);
            return AuthResult.failed("El compte està desactivat");
        }

        // Comprovar si el compte està bloquejat
        if (user.isLocked()) {
            long remainingSeconds = user.lockedUntil.getEpochSecond() - Instant.now().getEpochSecond();
            auditService.logLoginFailed(username,
                String.format("Account locked (%d seconds remaining)", remainingSeconds),
                ipAddress, userAgent);
            return AuthResult.failed(
                String.format("El compte està bloquejat. Torna-ho a provar en %d segons", remainingSeconds));
        }

        // Validar contrasenya
        if (!passwordHashService.verifyPassword(password, user.passwordHash)) {
            // Contrasenya incorrecta
            user.incrementFailedAttempts();

            // Bloquejar si supera el límit
            if (user.failedLoginAttempts >= maxFailedAttempts) {
                user.lockAccount(lockoutDuration);
                auditService.logAccountLocked(user,
                    String.format("%d failed login attempts", user.failedLoginAttempts),
                    ipAddress, userAgent);
                userRepository.update(user);
                return AuthResult.failed(
                    String.format("Massa intents fallits. Compte bloquejat durant %d segons", lockoutDuration));
            }

            userRepository.update(user);
            auditService.logLoginFailed(username, "Invalid password", ipAddress, userAgent);
            return AuthResult.failed("Credencials incorrectes");
        }

        // Comprovar si el 2FA està configurat
        if (!user.twoFactorEnabled || user.totpSecret == null) {
            auditService.logLoginFailed(username, "2FA not configured", ipAddress, userAgent);
            return AuthResult.failed("El 2FA no està configurat. Contacta amb un administrador");
        }

        // Credencials correctes! Reiniciar comptador d'intents
        user.resetFailedAttempts();
        userRepository.update(user);

        // Generar SessionToken temporal per la fase de 2FA
        // Aquest token només serveix per validar el 2FA, no per accedir a recursos
        String sessionToken = tokenService.generateAccessToken(user);

        LOG.debugf("Credentials validated for user: %s. Awaiting 2FA", username);

        return AuthResult.pendingTwoFactor(sessionToken, user.id.toString());
    }

    /**
     * Fase 2: Valida el codi 2FA i retorna els tokens finals.
     *
     * @param userId ID de l'usuari
     * @param totpCode codi TOTP de 6 dígits
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     * @return resultat amb Access Token i Refresh Token si és exitós
     */
    public AuthResult validate2FA(String userId, String totpCode,
                                 String ipAddress, String userAgent) {
        LOG.debugf("2FA validation attempt for user ID: %s", userId);

        // Buscar l'usuari
        User user = User.findById(new org.bson.types.ObjectId(userId));
        if (user == null || !user.active) {
            return AuthResult.failed("Usuari no trobat o inactiu");
        }

        // Validar el codi TOTP
        if (!totpService.validateCode(totpCode, user.totpSecret)) {
            auditService.log2FA(user, false, ipAddress, userAgent);
            return AuthResult.failed("Codi 2FA incorrecte");
        }

        // 2FA validat correctament!
        auditService.log2FA(user, true, ipAddress, userAgent);

        // Actualitzar informació de l'últim login
        user.lastLoginAt = Instant.now();
        user.lastLoginIp = ipAddress;
        user.lastDeviceFingerprint = calculateDeviceFingerprint(userAgent);
        userRepository.update(user);

        // Generar tokens finals (access + refresh)
        String deviceFingerprint = calculateDeviceFingerprint(userAgent);
        String accessToken = tokenService.generateAccessToken(user);
        String refreshToken = tokenService.generateRefreshToken(user, deviceFingerprint, ipAddress);

        auditService.logLoginSuccess(user, ipAddress, userAgent);

        LOG.infof("Login successful for user: %s", user.username);

        return AuthResult.success(accessToken, refreshToken, user);
    }

    /**
     * Renova els tokens utilitzant un Refresh Token.
     *
     * @param refreshToken refresh token actual
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     * @return nous tokens si és exitós
     */
    public AuthResult refreshTokens(String refreshToken, String ipAddress, String userAgent) {
        String deviceFingerprint = calculateDeviceFingerprint(userAgent);

        var tokenPair = tokenService.refreshTokens(refreshToken, deviceFingerprint, ipAddress);
        if (tokenPair == null) {
            LOG.warn("Token refresh failed");
            return AuthResult.failed("Token invàlid o expirat");
        }

        LOG.debug("Tokens refreshed successfully");

        return AuthResult.success(tokenPair.accessToken, tokenPair.refreshToken, null);
    }

    /**
     * Logout: revoca el Refresh Token.
     *
     * @param refreshToken token a revocar
     * @param user usuari (opcional, per auditoria)
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void logout(String refreshToken, User user, String ipAddress, String userAgent) {
        boolean revoked = tokenService.revokeRefreshToken(refreshToken, "User logout");

        if (user != null) {
            auditService.log(cat.minerva.model.AuditAction.LOGOUT, user, true,
                           "User logged out", ipAddress, userAgent);
        }

        LOG.debugf("Logout: token revoked=%s", revoked);
    }

    /**
     * Logout global: revoca tots els tokens d'un usuari.
     *
     * @param user usuari
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void logoutAll(User user, String ipAddress, String userAgent) {
        long count = tokenService.revokeAllUserTokens(user, "Global logout");

        auditService.log(cat.minerva.model.AuditAction.LOGOUT, user, true,
                       String.format("Global logout: %d tokens revoked", count),
                       ipAddress, userAgent);

        LOG.infof("Global logout for user %s: %d tokens revoked", user.username, count);
    }

    /**
     * Calcula un fingerprint del dispositiu basat en el user-agent.
     *
     * @param userAgent User-Agent del client
     * @return hash SHA-256
     */
    private String calculateDeviceFingerprint(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "";
        }

        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(userAgent.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            LOG.error("Error calculating device fingerprint", e);
            return "";
        }
    }

    /**
     * Classe per retornar resultats d'autenticació.
     */
    public static class AuthResult {
        public boolean success;
        public boolean pending2FA;
        public String message;
        public String sessionToken;  // Token temporal per 2FA
        public String accessToken;
        public String refreshToken;
        public String userId;
        public User user;

        public static AuthResult success(String accessToken, String refreshToken, User user) {
            AuthResult result = new AuthResult();
            result.success = true;
            result.accessToken = accessToken;
            result.refreshToken = refreshToken;
            result.user = user;
            return result;
        }

        public static AuthResult pendingTwoFactor(String sessionToken, String userId) {
            AuthResult result = new AuthResult();
            result.pending2FA = true;
            result.sessionToken = sessionToken;
            result.userId = userId;
            return result;
        }

        public static AuthResult failed(String message) {
            AuthResult result = new AuthResult();
            result.success = false;
            result.message = message;
            return result;
        }
    }
}
