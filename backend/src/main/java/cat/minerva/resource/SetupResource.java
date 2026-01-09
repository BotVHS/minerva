package cat.minerva.resource;

import cat.minerva.model.User;
import cat.minerva.model.UserRole;
import cat.minerva.repository.UserRepository;
import cat.minerva.security.PasswordHashService;
import cat.minerva.security.TotpService;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.Set;

/**
 * Endpoint especial per configuració inicial del sistema.
 *
 * IMPORTANT: Aquest endpoint només funciona quan NO hi ha cap usuari al sistema.
 * Després de crear el primer admin, aquest endpoint retornarà 403 Forbidden.
 *
 * Seguretat:
 * - Només es pot usar UNA VEGADA (quan la BD està buida)
 * - Requereix contrasenya forta
 * - L'admin ha de configurar 2FA immediatament després
 */
@Path("/api/setup")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class SetupResource {

    private static final Logger LOG = Logger.getLogger(SetupResource.class);

    @Inject
    UserRepository userRepository;

    @Inject
    PasswordHashService passwordHashService;

    @Inject
    TotpService totpService;

    /**
     * Crea el primer administrador del sistema.
     *
     * IMPORTANT: Aquest endpoint només funciona si NO hi ha cap usuari a la base de dades.
     *
     * POST /api/setup/first-admin
     *
     * Body:
     * {
     *   "username": "admin",
     *   "password": "SecurePassword123!@#",
     *   "email": "admin@example.com",
     *   "fullName": "System Administrator"
     * }
     *
     * Resposta:
     * {
     *   "success": true,
     *   "username": "admin",
     *   "totpQrCode": "data:image/png;base64,...",
     *   "message": "Admin creat correctament. Escaneja el QR code amb Google Authenticator."
     * }
     */
    @POST
    @Path("/first-admin")
    public Response createFirstAdmin(@Valid FirstAdminRequest request) {
        LOG.info("Attempting to create first admin user");

        // SEGURETAT: Només permetre si NO hi ha cap usuari
        long userCount = userRepository.count();
        if (userCount > 0) {
            LOG.warn("Attempted to create first admin but users already exist");
            return Response.status(Response.Status.FORBIDDEN)
                .entity(new ErrorResponse("El sistema ja té usuaris. Aquest endpoint està desactivat."))
                .build();
        }

        // Validar contrasenya
        String passwordError = passwordHashService.validatePassword(request.password);
        if (passwordError != null) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(new ErrorResponse(passwordError))
                .build();
        }

        try {
            // Crear l'usuari admin
            User admin = new User();
            admin.username = request.username;
            admin.email = request.email;
            admin.fullName = request.fullName;
            admin.passwordHash = passwordHashService.hashPassword(request.password);
            admin.roles = Set.of(UserRole.ADMIN);
            admin.active = true;
            admin.twoFactorEnabled = false;  // L'admin ho ha de configurar
            admin.createdAt = Instant.now();
            admin.updatedAt = Instant.now();
            admin.lastPasswordChangeAt = Instant.now();

            // Generar secret TOTP
            admin.totpSecret = totpService.generateSecret();

            // Guardar a la base de dades
            userRepository.persist(admin);

            // Generar QR code per 2FA
            String qrCode = totpService.generateQRCode(admin.username, admin.totpSecret);

            LOG.infof("First admin user created successfully: %s", admin.username);

            return Response.ok(new FirstAdminResponse(
                true,
                admin.username,
                admin.id.toString(),
                qrCode,
                "Administrador creat correctament! IMPORTANT:\n" +
                "1. Escaneja el QR code amb Google Authenticator o Authy\n" +
                "2. Usa l'endpoint POST /api/users/{userId}/enable-2fa per activar el 2FA\n" +
                "3. Després podràs fer login amb username, password i codi TOTP"
            )).build();

        } catch (Exception e) {
            LOG.error("Error creating first admin", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(new ErrorResponse("Error al crear l'administrador: " + e.getMessage()))
                .build();
        }
    }

    /**
     * Activa el 2FA per al primer admin (sense autenticació).
     *
     * IMPORTANT: Aquest endpoint només funciona si només hi ha 1 usuari al sistema
     * i aquest usuari NO té el 2FA activat.
     *
     * POST /api/setup/enable-first-admin-2fa
     *
     * Body:
     * {
     *   "username": "admin",
     *   "totpCode": "123456"
     * }
     */
    @POST
    @Path("/enable-first-admin-2fa")
    public Response enableFirstAdmin2FA(@Valid Enable2FARequest request) {
        LOG.infof("Attempting to enable 2FA for first admin: %s", request.username);

        // SEGURETAT: Només permetre si hi ha exactament 1 usuari
        long userCount = userRepository.count();
        if (userCount != 1) {
            LOG.warn("Attempted to use setup endpoint but user count is not 1");
            return Response.status(Response.Status.FORBIDDEN)
                .entity(new ErrorResponse("Aquest endpoint només funciona amb exactament 1 usuari al sistema."))
                .build();
        }

        // Buscar l'usuari
        var optionalUser = userRepository.findByUsername(request.username);
        if (optionalUser.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(new ErrorResponse("Usuari no trobat"))
                .build();
        }

        User user = optionalUser.get();

        // Comprovar que no té 2FA activat
        if (user.twoFactorEnabled) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(new ErrorResponse("El 2FA ja està activat"))
                .build();
        }

        // Validar el codi TOTP
        if (!totpService.validateCode(request.totpCode, user.totpSecret)) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(new ErrorResponse("Codi TOTP incorrecte. Assegura't que l'hora del teu dispositiu és correcta."))
                .build();
        }

        // Activar 2FA
        user.twoFactorEnabled = true;
        user.updatedAt = Instant.now();
        userRepository.update(user);

        LOG.infof("2FA enabled successfully for first admin: %s", user.username);

        return Response.ok(new SuccessResponse(
            true,
            "2FA activat correctament! Ara pots fer login amb:\n" +
            "1. POST /api/auth/login amb username i password\n" +
            "2. POST /api/auth/verify-2fa amb el userId, sessionToken i codi TOTP"
        )).build();
    }

    /**
     * Comprova si el sistema necessita configuració inicial.
     *
     * GET /api/setup/needs-setup
     *
     * Resposta:
     * {
     *   "needsSetup": true,
     *   "userCount": 0
     * }
     */
    @GET
    @Path("/needs-setup")
    public Response needsSetup() {
        long userCount = userRepository.count();
        return Response.ok(new NeedsSetupResponse(userCount == 0, userCount)).build();
    }

    // DTOs

    public static class FirstAdminRequest {
        @NotBlank(message = "Username is required")
        public String username;

        @NotBlank(message = "Password is required")
        public String password;

        public String email;
        public String fullName;
    }

    public static class FirstAdminResponse {
        public boolean success;
        public String username;
        public String userId;
        public String totpQrCode;
        public String message;

        public FirstAdminResponse(boolean success, String username, String userId, String totpQrCode, String message) {
            this.success = success;
            this.username = username;
            this.userId = userId;
            this.totpQrCode = totpQrCode;
            this.message = message;
        }
    }

    public static class NeedsSetupResponse {
        public boolean needsSetup;
        public long userCount;

        public NeedsSetupResponse(boolean needsSetup, long userCount) {
            this.needsSetup = needsSetup;
            this.userCount = userCount;
        }
    }

    public static class Enable2FARequest {
        @NotBlank(message = "Username is required")
        public String username;

        @NotBlank(message = "TOTP code is required")
        public String totpCode;
    }

    public static class SuccessResponse {
        public boolean success;
        public String message;

        public SuccessResponse(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    public static class ErrorResponse {
        public String error;

        public ErrorResponse(String error) {
            this.error = error;
        }
    }
}
