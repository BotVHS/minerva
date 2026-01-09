package cat.minerva.resource;

import cat.minerva.dto.request.LoginRequest;
import cat.minerva.dto.request.RefreshTokenRequest;
import cat.minerva.dto.request.Verify2FARequest;
import cat.minerva.dto.response.AuthResponse;
import cat.minerva.dto.response.UserDTO;
import cat.minerva.service.AuthService;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import org.jboss.logging.Logger;

/**
 * Endpoint REST per autenticació.
 *
 * Endpoints:
 * - POST /api/auth/login - Login amb credencials (Fase 1)
 * - POST /api/auth/verify-2fa - Validar 2FA (Fase 2)
 * - POST /api/auth/refresh - Renovar tokens
 * - POST /api/auth/logout - Logout
 */
@Path("/api/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {

    private static final Logger LOG = Logger.getLogger(AuthResource.class);

    @Inject
    AuthService authService;

    @Context
    jakarta.servlet.http.HttpServletRequest httpRequest;

    /**
     * Fase 1: Login amb usuari i contrasenya.
     *
     * POST /api/auth/login
     * Body: {"username": "...", "password": "..."}
     *
     * Resposta si correcte:
     * {
     *   "pending2FA": true,
     *   "sessionToken": "...",
     *   "userId": "...",
     *   "message": "Introdueix el codi 2FA"
     * }
     */
    @POST
    @Path("/login")
    public AuthResponse login(@Valid LoginRequest request) {
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        LOG.infof("Login attempt for user: %s from IP: %s", request.username, ipAddress);

        var result = authService.authenticateCredentials(
            request.username,
            request.password,
            ipAddress,
            userAgent
        );

        if (result.pending2FA) {
            return AuthResponse.pending2FA(result.sessionToken, result.userId);
        } else if (result.success) {
            return AuthResponse.success(
                result.accessToken,
                result.refreshToken,
                UserDTO.from(result.user)
            );
        } else {
            return AuthResponse.failed(result.message);
        }
    }

    /**
     * Fase 2: Validar codi 2FA.
     *
     * POST /api/auth/verify-2fa
     * Headers: Authorization: Bearer [sessionToken]
     * Body: {"userId": "...", "totpCode": "123456"}
     *
     * Resposta si correcte:
     * {
     *   "success": true,
     *   "accessToken": "...",
     *   "refreshToken": "...",
     *   "user": {...}
     * }
     */
    @POST
    @Path("/verify-2fa")
    public AuthResponse verify2FA(@Valid Verify2FARequest request) {
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        LOG.infof("2FA verification attempt for user ID: %s", request.userId);

        var result = authService.validate2FA(
            request.userId,
            request.totpCode,
            ipAddress,
            userAgent
        );

        if (result.success) {
            return AuthResponse.success(
                result.accessToken,
                result.refreshToken,
                UserDTO.from(result.user)
            );
        } else {
            return AuthResponse.failed(result.message);
        }
    }

    /**
     * Renovar tokens amb refresh token.
     *
     * POST /api/auth/refresh
     * Body: {"refreshToken": "..."}
     *
     * Resposta:
     * {
     *   "success": true,
     *   "accessToken": "...",  (nou)
     *   "refreshToken": "..."  (nou, rotació automàtica)
     * }
     */
    @POST
    @Path("/refresh")
    public AuthResponse refresh(@Valid RefreshTokenRequest request) {
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        LOG.debug("Token refresh attempt");

        var result = authService.refreshTokens(
            request.refreshToken,
            ipAddress,
            userAgent
        );

        if (result.success) {
            return AuthResponse.success(
                result.accessToken,
                result.refreshToken,
                null  // No retornem user info en refresh
            );
        } else {
            return AuthResponse.failed(result.message);
        }
    }

    /**
     * Logout: revoca el refresh token.
     *
     * POST /api/auth/logout
     * Headers: Authorization: Bearer [accessToken]
     * Body: {"refreshToken": "..."}
     */
    @POST
    @Path("/logout")
    public jakarta.ws.rs.core.Response logout(
        @Valid RefreshTokenRequest request,
        @Context SecurityContext securityContext
    ) {
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        LOG.debug("Logout attempt");

        // Obtenir usuari del security context (si està autenticat)
        var user = getCurrentUser(securityContext);

        authService.logout(request.refreshToken, user, ipAddress, userAgent);

        return jakarta.ws.rs.core.Response
            .ok()
            .entity(new LogoutResponse(true, "Logout successful"))
            .build();
    }

    /**
     * Obté la IP del client.
     */
    private String getClientIp() {
        // Comprovar si hi ha proxy (X-Forwarded-For)
        String forwardedFor = httpRequest.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            return forwardedFor.split(",")[0].trim();
        }

        String realIp = httpRequest.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isEmpty()) {
            return realIp;
        }

        return httpRequest.getRemoteAddr();
    }

    /**
     * Obté el User-Agent del client.
     */
    private String getUserAgent() {
        String userAgent = httpRequest.getHeader("User-Agent");
        return userAgent != null ? userAgent : "Unknown";
    }

    /**
     * Obté l'usuari actual del security context.
     */
    private cat.minerva.model.User getCurrentUser(SecurityContext securityContext) {
        if (securityContext == null || securityContext.getUserPrincipal() == null) {
            return null;
        }

        String userId = securityContext.getUserPrincipal().getName();
        return cat.minerva.model.User.findById(new org.bson.types.ObjectId(userId));
    }

    /**
     * DTO per resposta de logout.
     */
    public static class LogoutResponse {
        public boolean success;
        public String message;

        public LogoutResponse(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }
}
