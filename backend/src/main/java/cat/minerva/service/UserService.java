package cat.minerva.service;

import cat.minerva.audit.AuditService;
import cat.minerva.model.AuditAction;
import cat.minerva.model.User;
import cat.minerva.model.UserRole;
import cat.minerva.repository.UserRepository;
import cat.minerva.security.PasswordHashService;
import cat.minerva.security.TotpService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Servei per gestionar usuaris.
 *
 * Funcionalitats:
 * - Crear usuaris (només administradors)
 * - Modificar usuaris
 * - Assignar/eliminar rols
 * - Activar/desactivar comptes
 * - Configurar 2FA
 * - Reset de contrasenyes
 *
 * Seguretat:
 * - No hi ha registre públic
 * - Només administradors poden crear usuaris
 * - Totes les accions queden auditades
 * - Contrasenyes temporals que cal canviar
 * - 2FA obligatori abans del primer login complet
 */
@ApplicationScoped
public class UserService {

    private static final Logger LOG = Logger.getLogger(UserService.class);

    @Inject
    UserRepository userRepository;

    @Inject
    PasswordHashService passwordHashService;

    @Inject
    TotpService totpService;

    @Inject
    AuditService auditService;

    /**
     * Crea un nou usuari (només administradors).
     *
     * El procés:
     * 1. Genera una contrasenya temporal
     * 2. Crea l'usuari amb rols assignats
     * 3. Prepara el 2FA (l'usuari l'ha de configurar)
     * 4. Registra l'acció en els logs
     *
     * @param admin administrador que crea l'usuari
     * @param username nom d'usuari
     * @param email email (opcional)
     * @param fullName nom complet (opcional)
     * @param roles rols a assignar
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     * @return nou usuari creat amb contrasenya temporal
     */
    publicCreateUserResult createUser(User admin, String username, String email, String fullName,
                                      Set<UserRole> roles, String ipAddress, String userAgent) {
        LOG.infof("Creating new user: %s by admin: %s", username, admin.username);

        // Comprovar que l'admin té permisos
        if (!admin.isAdmin()) {
            throw new SecurityException("Only administrators can create users");
        }

        // Comprovar que el username no existeix
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists");
        }

        // Generar contrasenya temporal
        String temporaryPassword = passwordHashService.generateTemporaryPassword();
        String passwordHash = passwordHashService.hashPassword(temporaryPassword);

        // Crear usuari
        User user = new User();
        user.username = username;
        user.email = email;
        user.fullName = fullName;
        user.passwordHash = passwordHash;
        user.roles = roles != null && !roles.isEmpty() ? roles : Set.of(UserRole.CONTRIBUIDOR);
        user.active = true;
        user.twoFactorEnabled = false; // L'usuari ho ha de configurar
        user.createdAt = Instant.now();
        user.updatedAt = Instant.now();

        // Generar secret TOTP (però no activar fins que l'usuari el configuri)
        user.totpSecret = totpService.generateSecret();

        userRepository.persist(user);

        // Auditar creació
        auditService.logUserCreated(admin, user, ipAddress, userAgent);

        LOG.infof("User created successfully: %s with roles: %s", username, user.roles);

        return new CreateUserResult(user, temporaryPassword);
    }

    /**
     * Setup 2FA per un usuari.
     *
     * Genera el QR code que l'usuari ha d'escannejar amb la seva app.
     *
     * @param user usuari
     * @return QR code en Base64
     */
    public String setup2FA(User user) {
        if (user.totpSecret == null) {
            user.totpSecret = totpService.generateSecret();
            userRepository.update(user);
        }

        return totpService.generateQRCode(user.username, user.totpSecret);
    }

    /**
     * Activa el 2FA després que l'usuari hagi escannejat el QR i validat el primer codi.
     *
     * @param user usuari
     * @param totpCode codi TOTP de validació
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     * @return true si s'ha activat correctament
     */
    publicboolean enable2FA(User user, String totpCode, String ipAddress, String userAgent) {
        if (user.totpSecret == null) {
            throw new IllegalStateException("TOTP secret not configured");
        }

        // Validar el codi abans d'activar
        if (!totpService.validateCode(totpCode, user.totpSecret)) {
            auditService.log(AuditAction.TWO_FA_SETUP, user, false,
                           "2FA setup failed: invalid code", ipAddress, userAgent);
            return false;
        }

        user.twoFactorEnabled = true;
        user.updatedAt = Instant.now();
        userRepository.update(user);

        auditService.log(AuditAction.TWO_FA_ENABLED, user, true,
                       "2FA enabled successfully", ipAddress, userAgent);

        LOG.infof("2FA enabled for user: %s", user.username);
        return true;
    }

    /**
     * Reset del 2FA per un usuari (només administradors).
     *
     * Utilitzat quan un usuari perd accés a la seva app d'autenticació.
     *
     * @param admin administrador
     * @param targetUser usuari al qual fer reset
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     * @return nou secret TOTP
     */
    publicString reset2FA(User admin, User targetUser, String ipAddress, String userAgent) {
        if (!admin.isAdmin()) {
            throw new SecurityException("Only administrators can reset 2FA");
        }

        // Generar nou secret
        targetUser.totpSecret = totpService.generateSecret();
        targetUser.twoFactorEnabled = false; // Cal reconfigurar
        targetUser.updatedAt = Instant.now();
        userRepository.update(targetUser);

        auditService.log(AuditAction.TWO_FA_RESET, admin, true,
                       String.format("2FA reset for user: %s", targetUser.username),
                       ipAddress, userAgent, null, targetUser.id, "USER");

        LOG.infof("2FA reset for user: %s by admin: %s", targetUser.username, admin.username);

        return totpService.generateQRCode(targetUser.username, targetUser.totpSecret);
    }

    /**
     * Canvia la contrasenya d'un usuari.
     *
     * @param user usuari
     * @param oldPassword contrasenya antiga
     * @param newPassword nova contrasenya
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     * @return true si s'ha canviat correctament
     */
    publicboolean changePassword(User user, String oldPassword, String newPassword,
                                 String ipAddress, String userAgent) {
        // Validar contrasenya antiga
        if (!passwordHashService.verifyPassword(oldPassword, user.passwordHash)) {
            auditService.log(AuditAction.PASSWORD_CHANGED, user, false,
                           "Password change failed: invalid old password",
                           ipAddress, userAgent);
            return false;
        }

        // Validar nova contrasenya
        String validationError = passwordHashService.validatePassword(newPassword);
        if (validationError != null) {
            throw new IllegalArgumentException(validationError);
        }

        // Actualitzar contrasenya
        user.passwordHash = passwordHashService.hashPassword(newPassword);
        user.lastPasswordChangeAt = Instant.now();
        user.updatedAt = Instant.now();
        userRepository.update(user);

        auditService.log(AuditAction.PASSWORD_CHANGED, user, true,
                       "Password changed successfully", ipAddress, userAgent);

        LOG.infof("Password changed for user: %s", user.username);
        return true;
    }

    /**
     * Assigna un rol a un usuari (només administradors).
     *
     * @param admin administrador
     * @param targetUser usuari
     * @param role rol a assignar
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    publicvoid assignRole(User admin, User targetUser, UserRole role,
                          String ipAddress, String userAgent) {
        if (!admin.isAdmin()) {
            throw new SecurityException("Only administrators can assign roles");
        }

        if (targetUser.roles == null) {
            targetUser.roles = new HashSet<>();
        }

        targetUser.roles.add(role);
        targetUser.updatedAt = Instant.now();
        userRepository.update(targetUser);

        auditService.logRoleAssigned(admin, targetUser, role.name(), ipAddress, userAgent);

        LOG.infof("Role %s assigned to user: %s by admin: %s", role, targetUser.username, admin.username);
    }

    /**
     * Elimina un rol d'un usuari (només administradors).
     *
     * @param admin administrador
     * @param targetUser usuari
     * @param role rol a eliminar
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    publicvoid removeRole(User admin, User targetUser, UserRole role,
                          String ipAddress, String userAgent) {
        if (!admin.isAdmin()) {
            throw new SecurityException("Only administrators can remove roles");
        }

        if (targetUser.roles != null) {
            targetUser.roles.remove(role);
            targetUser.updatedAt = Instant.now();
            userRepository.update(targetUser);
        }

        auditService.log(AuditAction.ROLE_REMOVED, admin, true,
                       String.format("Role %s removed from user: %s", role, targetUser.username),
                       ipAddress, userAgent, null, targetUser.id, "USER");

        LOG.infof("Role %s removed from user: %s by admin: %s", role, targetUser.username, admin.username);
    }

    /**
     * Activa un compte d'usuari (només administradors).
     *
     * @param admin administrador
     * @param targetUser usuari
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    publicvoid enableUser(User admin, User targetUser, String ipAddress, String userAgent) {
        if (!admin.isAdmin()) {
            throw new SecurityException("Only administrators can enable users");
        }

        targetUser.active = true;
        targetUser.updatedAt = Instant.now();
        userRepository.update(targetUser);

        auditService.log(AuditAction.USER_ENABLED, admin, true,
                       String.format("User %s enabled", targetUser.username),
                       ipAddress, userAgent, null, targetUser.id, "USER");

        LOG.infof("User %s enabled by admin: %s", targetUser.username, admin.username);
    }

    /**
     * Desactiva un compte d'usuari (només administradors).
     *
     * @param admin administrador
     * @param targetUser usuari
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    publicvoid disableUser(User admin, User targetUser, String ipAddress, String userAgent) {
        if (!admin.isAdmin()) {
            throw new SecurityException("Only administrators can disable users");
        }

        targetUser.active = false;
        targetUser.updatedAt = Instant.now();
        userRepository.update(targetUser);

        auditService.log(AuditAction.USER_DISABLED, admin, true,
                       String.format("User %s disabled", targetUser.username),
                       ipAddress, userAgent, null, targetUser.id, "USER");

        LOG.infof("User %s disabled by admin: %s", targetUser.username, admin.username);
    }

    /**
     * Desbloqueja un compte (només administradors).
     *
     * @param admin administrador
     * @param targetUser usuari
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    publicvoid unlockUser(User admin, User targetUser, String ipAddress, String userAgent) {
        if (!admin.isAdmin()) {
            throw new SecurityException("Only administrators can unlock users");
        }

        targetUser.unlockAccount();
        targetUser.updatedAt = Instant.now();
        userRepository.update(targetUser);

        auditService.log(AuditAction.ACCOUNT_UNLOCKED, admin, true,
                       String.format("User %s unlocked", targetUser.username),
                       ipAddress, userAgent, null, targetUser.id, "USER");

        LOG.infof("User %s unlocked by admin: %s", targetUser.username, admin.username);
    }

    /**
     * Troba un usuari pel seu ID.
     *
     * @param userId ID de l'usuari
     * @return usuari
     */
    public Optional<User> findById(String userId) {
        return Optional.ofNullable(User.findById(new org.bson.types.ObjectId(userId)));
    }

    /**
     * Troba un usuari pel seu nom d'usuari.
     *
     * @param username nom d'usuari
     * @return usuari
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Llista tots els usuaris (només administradors).
     *
     * @return llista d'usuaris
     */
    public List<User> listAllUsers() {
        return userRepository.listAll();
    }

    /**
     * Llista usuaris actius.
     *
     * @return llista d'usuaris actius
     */
    public List<User> listActiveUsers() {
        return userRepository.findAllActive();
    }

    /**
     * Classe per retornar resultat de creació d'usuari.
     */
    public static class CreateUserResult {
        public final User user;
        public final String temporaryPassword;

        public CreateUserResult(User user, String temporaryPassword) {
            this.user = user;
            this.temporaryPassword = temporaryPassword;
        }
    }
}
