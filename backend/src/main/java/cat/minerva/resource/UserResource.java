package cat.minerva.resource;

import cat.minerva.dto.request.CreateUserRequest;
import cat.minerva.dto.response.UserDTO;
import cat.minerva.model.User;
import cat.minerva.model.UserRole;
import cat.minerva.service.UserService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import org.jboss.logging.Logger;
import io.vertx.core.http.HttpServerRequest;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Endpoint REST per gestió d'usuaris (només administradors).
 *
 * Endpoints:
 * - POST /api/users - Crear usuari
 * - GET /api/users - Llistar usuaris
 * - GET /api/users/{id} - Obtenir usuari
 * - POST /api/users/{id}/roles - Assignar rol
 * - DELETE /api/users/{id}/roles/{role} - Eliminar rol
 * - POST /api/users/{id}/enable - Activar usuari
 * - POST /api/users/{id}/disable - Desactivar usuari
 * - POST /api/users/{id}/unlock - Desbloquejar usuari
 * - POST /api/users/{id}/reset-2fa - Reset 2FA
 */
@Path("/api/users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserResource {

    private static final Logger LOG = Logger.getLogger(UserResource.class);

    @Inject
    UserService userService;

    @Context
    HttpServerRequest request;

    /**
     * Crear nou usuari (només ADMIN).
     *
     * POST /api/users
     * Body: {
     *   "username": "maria.garcia",
     *   "email": "maria@gov.cat",
     *   "fullName": "Maria Garcia",
     *   "roles": ["ANALISTA"]
     * }
     *
     * Resposta:
     * {
     *   "success": true,
     *   "user": {...},
     *   "temporaryPassword": "Xy9$mK2#pL5@qW8!",
     *   "message": "Usuari creat. Contrasenya temporal: ..."
     * }
     */
    @POST
    @RolesAllowed("ADMIN")
    public CreateUserResponse createUser(
        @Valid CreateUserRequest request,
        @Context SecurityContext securityContext
    ) {
        User admin = getCurrentUser(securityContext);
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        LOG.infof("Creating user: %s by admin: %s", request.username, admin.username);

        var result = userService.createUser(
            admin,
            request.username,
            request.email,
            request.fullName,
            request.roles,
            ipAddress,
            userAgent
        );

        return new CreateUserResponse(
            true,
            UserDTO.from(result.user),
            result.temporaryPassword,
            String.format("Usuari creat. Contrasenya temporal: %s", result.temporaryPassword)
        );
    }

    /**
     * Llistar tots els usuaris (ADMIN i SUPERVISOR).
     *
     * GET /api/users
     */
    @GET
    @RolesAllowed({"ADMIN", "SUPERVISOR"})
    public List<UserDTO> listUsers() {
        LOG.debug("Listing all users");

        return userService.listAllUsers()
            .stream()
            .map(UserDTO::from)
            .collect(Collectors.toList());
    }

    /**
     * Obtenir usuari per ID.
     *
     * GET /api/users/{id}
     */
    @GET
    @Path("/{id}")
    @RolesAllowed({"ADMIN", "SUPERVISOR"})
    public UserDTO getUser(@PathParam("id") String id) {
        LOG.debugf("Getting user: %s", id);

        return userService.findById(id)
            .map(UserDTO::from)
            .orElseThrow(() -> new NotFoundException("User not found"));
    }

    /**
     * Assignar rol a usuari (només ADMIN).
     *
     * POST /api/users/{id}/roles
     * Body: {"role": "SUPERVISOR"}
     */
    @POST
    @Path("/{id}/roles")
    @RolesAllowed("ADMIN")
    public jakarta.ws.rs.core.Response assignRole(
        @PathParam("id") String id,
        AssignRoleRequest request,
        @Context SecurityContext securityContext
    ) {
        User admin = getCurrentUser(securityContext);
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        User targetUser = userService.findById(id)
            .orElseThrow(() -> new NotFoundException("User not found"));

        LOG.infof("Assigning role %s to user: %s by admin: %s",
                  request.role, targetUser.username, admin.username);

        userService.assignRole(admin, targetUser, request.role, ipAddress, userAgent);

        return jakarta.ws.rs.core.Response
            .ok()
            .entity(new SimpleResponse(true, "Role assigned successfully"))
            .build();
    }

    /**
     * Eliminar rol d'usuari (només ADMIN).
     *
     * DELETE /api/users/{id}/roles/{role}
     */
    @DELETE
    @Path("/{id}/roles/{role}")
    @RolesAllowed("ADMIN")
    public jakarta.ws.rs.core.Response removeRole(
        @PathParam("id") String id,
        @PathParam("role") String roleName,
        @Context SecurityContext securityContext
    ) {
        User admin = getCurrentUser(securityContext);
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        User targetUser = userService.findById(id)
            .orElseThrow(() -> new NotFoundException("User not found"));

        UserRole role = UserRole.valueOf(roleName);

        LOG.infof("Removing role %s from user: %s by admin: %s",
                  role, targetUser.username, admin.username);

        userService.removeRole(admin, targetUser, role, ipAddress, userAgent);

        return jakarta.ws.rs.core.Response
            .ok()
            .entity(new SimpleResponse(true, "Role removed successfully"))
            .build();
    }

    /**
     * Activar usuari (només ADMIN).
     *
     * POST /api/users/{id}/enable
     */
    @POST
    @Path("/{id}/enable")
    @RolesAllowed("ADMIN")
    public jakarta.ws.rs.core.Response enableUser(
        @PathParam("id") String id,
        @Context SecurityContext securityContext
    ) {
        User admin = getCurrentUser(securityContext);
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        User targetUser = userService.findById(id)
            .orElseThrow(() -> new NotFoundException("User not found"));

        LOG.infof("Enabling user: %s by admin: %s", targetUser.username, admin.username);

        userService.enableUser(admin, targetUser, ipAddress, userAgent);

        return jakarta.ws.rs.core.Response
            .ok()
            .entity(new SimpleResponse(true, "User enabled successfully"))
            .build();
    }

    /**
     * Desactivar usuari (només ADMIN).
     *
     * POST /api/users/{id}/disable
     */
    @POST
    @Path("/{id}/disable")
    @RolesAllowed("ADMIN")
    public jakarta.ws.rs.core.Response disableUser(
        @PathParam("id") String id,
        @Context SecurityContext securityContext
    ) {
        User admin = getCurrentUser(securityContext);
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        User targetUser = userService.findById(id)
            .orElseThrow(() -> new NotFoundException("User not found"));

        LOG.infof("Disabling user: %s by admin: %s", targetUser.username, admin.username);

        userService.disableUser(admin, targetUser, ipAddress, userAgent);

        return jakarta.ws.rs.core.Response
            .ok()
            .entity(new SimpleResponse(true, "User disabled successfully"))
            .build();
    }

    /**
     * Desbloquejar usuari (només ADMIN).
     *
     * POST /api/users/{id}/unlock
     */
    @POST
    @Path("/{id}/unlock")
    @RolesAllowed("ADMIN")
    public jakarta.ws.rs.core.Response unlockUser(
        @PathParam("id") String id,
        @Context SecurityContext securityContext
    ) {
        User admin = getCurrentUser(securityContext);
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        User targetUser = userService.findById(id)
            .orElseThrow(() -> new NotFoundException("User not found"));

        LOG.infof("Unlocking user: %s by admin: %s", targetUser.username, admin.username);

        userService.unlockUser(admin, targetUser, ipAddress, userAgent);

        return jakarta.ws.rs.core.Response
            .ok()
            .entity(new SimpleResponse(true, "User unlocked successfully"))
            .build();
    }

    /**
     * Reset 2FA (només ADMIN).
     *
     * POST /api/users/{id}/reset-2fa
     *
     * Resposta:
     * {
     *   "success": true,
     *   "qrCode": "data:image/png;base64,...",
     *   "message": "2FA reset. L'usuari ha d'escanejar el nou QR code"
     * }
     */
    @POST
    @Path("/{id}/reset-2fa")
    @RolesAllowed("ADMIN")
    public Reset2FAResponse reset2FA(
        @PathParam("id") String id,
        @Context SecurityContext securityContext
    ) {
        User admin = getCurrentUser(securityContext);
        String ipAddress = getClientIp();
        String userAgent = getUserAgent();

        User targetUser = userService.findById(id)
            .orElseThrow(() -> new NotFoundException("User not found"));

        LOG.infof("Resetting 2FA for user: %s by admin: %s",
                  targetUser.username, admin.username);

        String qrCode = userService.reset2FA(admin, targetUser, ipAddress, userAgent);

        return new Reset2FAResponse(
            true,
            qrCode,
            "2FA reset. L'usuari ha d'escanejar el nou QR code"
        );
    }

    // Helper methods

    private User getCurrentUser(SecurityContext securityContext) {
        String userId = securityContext.getUserPrincipal().getName();
        return User.findById(new org.bson.types.ObjectId(userId));
    }

    private String getClientIp() {
        // Comprovar si hi ha proxy (X-Forwarded-For)
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            return forwardedFor.split(",")[0].trim();
        }

        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isEmpty()) {
            return realIp;
        }

        return request.remoteAddress().host();
    }

    private String getUserAgent() {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "Unknown";
    }

    // DTOs

    public static class CreateUserResponse {
        public boolean success;
        public UserDTO user;
        public String temporaryPassword;
        public String message;

        public CreateUserResponse(boolean success, UserDTO user,
                                 String temporaryPassword, String message) {
            this.success = success;
            this.user = user;
            this.temporaryPassword = temporaryPassword;
            this.message = message;
        }
    }

    public static class AssignRoleRequest {
        public UserRole role;
    }

    public static class SimpleResponse {
        public boolean success;
        public String message;

        public SimpleResponse(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    public static class Reset2FAResponse {
        public boolean success;
        public String qrCode;
        public String message;

        public Reset2FAResponse(boolean success, String qrCode, String message) {
            this.success = success;
            this.qrCode = qrCode;
            this.message = message;
        }
    }
}
