package cat.minerva.audit;

import cat.minerva.model.AuditAction;
import cat.minerva.model.AuditLog;
import cat.minerva.model.User;
import cat.minerva.repository.AuditLogRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.bson.types.ObjectId;
import org.jboss.logging.Logger;

import java.time.Instant;

/**
 * Servei per gestionar logs d'auditoria immutables.
 *
 * Aquest servei implementa un sistema de logs tipus blockchain:
 * - Cada entrada conté un hash del seu contingut + hash de l'entrada anterior
 * - La cadena de hashs fa que qualsevol modificació sigui detectable
 * - Col·lecció append-only (només afegir, mai modificar/eliminar)
 *
 * Totes les accions crítiques del sistema passen per aquest servei
 * per garantir traçabilitat completa i resistència a manipulacions.
 */
@ApplicationScoped
public class AuditService {

    private static final Logger LOG = Logger.getLogger(AuditService.class);

    @Inject
    AuditLogRepository auditLogRepository;

    /**
     * Registra una acció en el log d'auditoria.
     *
     * @param action tipus d'acció
     * @param user usuari que fa l'acció (pot ser null per accions anònimes)
     * @param success si l'acció ha tingut èxit
     * @param details detalls addicionals
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void log(AuditAction action, User user, boolean success, String details,
                    String ipAddress, String userAgent) {
        log(action, user, success, details, ipAddress, userAgent, null, null, null);
    }

    /**
     * Registra una acció en el log d'auditoria amb informació completa.
     *
     * @param action tipus d'acció
     * @param user usuari que fa l'acció (pot ser null)
     * @param success si l'acció ha tingut èxit
     * @param details detalls addicionals
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     * @param errorMessage missatge d'error si n'hi ha
     * @param targetResourceId ID del recurs afectat
     * @param targetResourceType tipus del recurs afectat
     */
    public void log(AuditAction action, User user, boolean success, String details,
                    String ipAddress, String userAgent, String errorMessage,
                    ObjectId targetResourceId, String targetResourceType) {

        try {
            AuditLog log = new AuditLog();

            // Informació de l'acció
            log.action = action;
            log.timestamp = Instant.now();
            log.success = success;
            log.details = details;
            log.errorMessage = errorMessage;

            // Informació de l'usuari
            if (user != null) {
                log.userId = user.id;
                log.username = user.username;
                log.userRoles = user.roles.toString();
            }

            // Informació del client
            log.ipAddress = ipAddress;
            log.userAgent = userAgent;
            log.deviceFingerprint = calculateDeviceFingerprint(userAgent);

            // Informació del recurs afectat
            log.targetResourceId = targetResourceId;
            log.targetResourceType = targetResourceType;

            // Obtenir l'últim log per la cadena de hashs
            var lastLog = auditLogRepository.findLatest();
            log.previousHash = lastLog.map(l -> l.currentHash).orElse("");
            log.sequenceNumber = auditLogRepository.getNextSequenceNumber();

            // Calcular el hash d'aquesta entrada
            log.currentHash = log.calculateHash();

            // Guardar el log
            auditLogRepository.persist(log);

            LOG.debugf("Audit log created: action=%s, user=%s, success=%s, seq=%d",
                      action, user != null ? user.username : "anonymous", success, log.sequenceNumber);

        } catch (Exception e) {
            // Els errors en logging NO han de trencar l'aplicació
            // però els registrem per investigació
            LOG.error("Failed to create audit log", e);
        }
    }

    /**
     * Registra un login exitós.
     *
     * @param user usuari que ha fet login
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void logLoginSuccess(User user, String ipAddress, String userAgent) {
        log(AuditAction.LOGIN_SUCCESS, user, true,
            String.format("Login exitós des de %s", ipAddress),
            ipAddress, userAgent);
    }

    /**
     * Registra un login fallit.
     *
     * @param username nom d'usuari intentat
     * @param reason raó del falliment
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void logLoginFailed(String username, String reason, String ipAddress, String userAgent) {
        AuditLog log = new AuditLog();
        log.action = AuditAction.LOGIN_FAILED;
        log.timestamp = Instant.now();
        log.success = false;
        log.username = username;
        log.details = String.format("Login fallit: %s", reason);
        log.errorMessage = reason;
        log.ipAddress = ipAddress;
        log.userAgent = userAgent;
        log.deviceFingerprint = calculateDeviceFingerprint(userAgent);

        var lastLog = auditLogRepository.findLatest();
        log.previousHash = lastLog.map(l -> l.currentHash).orElse("");
        log.sequenceNumber = auditLogRepository.getNextSequenceNumber();
        log.currentHash = log.calculateHash();

        auditLogRepository.persist(log);
    }

    /**
     * Registra validació 2FA.
     *
     * @param user usuari
     * @param success si ha tingut èxit
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void log2FA(User user, boolean success, String ipAddress, String userAgent) {
        log(success ? AuditAction.TWO_FA_SUCCESS : AuditAction.TWO_FA_FAILED,
            user, success,
            success ? "2FA validat correctament" : "2FA validació fallida",
            ipAddress, userAgent);
    }

    /**
     * Registra creació d'usuari.
     *
     * @param admin administrador que crea l'usuari
     * @param newUser nou usuari creat
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void logUserCreated(User admin, User newUser, String ipAddress, String userAgent) {
        log(AuditAction.USER_CREATED, admin, true,
            String.format("Usuari '%s' creat amb rols: %s", newUser.username, newUser.roles),
            ipAddress, userAgent, null, newUser.id, "USER");
    }

    /**
     * Registra modificació d'usuari.
     *
     * @param admin administrador que modifica
     * @param modifiedUser usuari modificat
     * @param changes canvis realitzats
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void logUserUpdated(User admin, User modifiedUser, String changes,
                              String ipAddress, String userAgent) {
        log(AuditAction.USER_UPDATED, admin, true,
            String.format("Usuari '%s' modificat: %s", modifiedUser.username, changes),
            ipAddress, userAgent, null, modifiedUser.id, "USER");
    }

    /**
     * Registra assignació de rol.
     *
     * @param admin administrador que assigna
     * @param targetUser usuari al qual s'assigna
     * @param role rol assignat
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void logRoleAssigned(User admin, User targetUser, String role,
                               String ipAddress, String userAgent) {
        log(AuditAction.ROLE_ASSIGNED, admin, true,
            String.format("Rol '%s' assignat a usuari '%s'", role, targetUser.username),
            ipAddress, userAgent, null, targetUser.id, "USER");
    }

    /**
     * Registra activitat sospitosa.
     *
     * @param user usuari (pot ser null)
     * @param description descripció de l'activitat sospitosa
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void logSuspiciousActivity(User user, String description,
                                     String ipAddress, String userAgent) {
        log(AuditAction.SUSPICIOUS_ACTIVITY_DETECTED, user, false,
            description, ipAddress, userAgent);
    }

    /**
     * Registra bloqueig de compte.
     *
     * @param user usuari bloquejat
     * @param reason raó del bloqueig
     * @param ipAddress IP del client
     * @param userAgent User-Agent del client
     */
    public void logAccountLocked(User user, String reason, String ipAddress, String userAgent) {
        log(AuditAction.ACCOUNT_LOCKED, user, true,
            String.format("Compte bloquejat: %s", reason),
            ipAddress, userAgent);
    }

    /**
     * Verifica la integritat de la cadena de logs.
     *
     * @return true si la cadena és íntegra, false si s'ha detectat manipulació
     */
    public boolean verifyIntegrity() {
        LOG.info("Starting audit log chain integrity verification...");
        boolean isValid = auditLogRepository.verifyChainIntegrity();
        LOG.infof("Audit log chain integrity: %s", isValid ? "VALID" : "COMPROMISED");
        return isValid;
    }

    /**
     * Calcula un fingerprint del dispositiu basat en el user-agent.
     *
     * @param userAgent User-Agent del client
     * @return hash SHA-256 del user-agent
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
        } catch (java.security.NoSuchAlgorithmException e) {
            LOG.error("SHA-256 algorithm not found", e);
            return "";
        }
    }
}
