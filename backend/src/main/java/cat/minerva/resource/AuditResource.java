package cat.minerva.resource;

import cat.minerva.model.AuditLog;
import cat.minerva.repository.AuditLogRepository;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.List;

/**
 * Endpoint REST per consultar logs d'auditoria (només ADMIN i SUPERVISOR).
 *
 * Els logs són read-only i immutables.
 *
 * Endpoints:
 * - GET /api/audit/logs - Tots els logs
 * - GET /api/audit/logs/user/{userId} - Logs d'un usuari
 * - GET /api/audit/logs/failed-logins - Intents fallits
 * - GET /api/audit/logs/suspicious - Activitat sospitosa
 * - POST /api/audit/verify-integrity - Verificar integritat
 */
@Path("/api/audit")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RolesAllowed({"ADMIN", "SUPERVISOR"})
public class AuditResource {

    private static final Logger LOG = Logger.getLogger(AuditResource.class);

    @Inject
    AuditLogRepository auditLogRepository;

    @Inject
    cat.minerva.audit.AuditService auditService;

    /**
     * Obtenir tots els logs d'auditoria.
     *
     * GET /api/audit/logs
     *
     * Query params opcionals:
     * - from: timestamp inicial (ISO 8601)
     * - to: timestamp final (ISO 8601)
     * - limit: nombre màxim de resultats (per defecte 100)
     */
    @GET
    @Path("/logs")
    public LogsResponse getLogs(
        @QueryParam("from") String fromStr,
        @QueryParam("to") String toStr,
        @QueryParam("limit") @DefaultValue("100") int limit
    ) {
        LOG.debug("Fetching audit logs");

        List<AuditLog> logs;

        if (fromStr != null && toStr != null) {
            Instant from = Instant.parse(fromStr);
            Instant to = Instant.parse(toStr);
            logs = auditLogRepository.findByDateRange(from, to);
        } else {
            logs = auditLogRepository.listAll();
        }

        // Limitar resultats
        if (logs.size() > limit) {
            logs = logs.subList(0, limit);
        }

        return new LogsResponse(logs, logs.size());
    }

    /**
     * Logs d'un usuari específic.
     *
     * GET /api/audit/logs/user/{userId}
     */
    @GET
    @Path("/logs/user/{userId}")
    public LogsResponse getUserLogs(@PathParam("userId") String userId) {
        LOG.debugf("Fetching logs for user: %s", userId);

        var logs = auditLogRepository.findByUserId(new org.bson.types.ObjectId(userId));

        return new LogsResponse(logs, logs.size());
    }

    /**
     * Intents de login fallits.
     *
     * GET /api/audit/logs/failed-logins
     */
    @GET
    @Path("/logs/failed-logins")
    public LogsResponse getFailedLogins() {
        LOG.debug("Fetching failed login attempts");

        var logs = auditLogRepository.findFailedLogins();

        return new LogsResponse(logs, logs.size());
    }

    /**
     * Activitat sospitosa.
     *
     * GET /api/audit/logs/suspicious
     */
    @GET
    @Path("/logs/suspicious")
    public LogsResponse getSuspiciousActivity() {
        LOG.debug("Fetching suspicious activity");

        var logs = auditLogRepository.findSuspiciousActivity();

        return new LogsResponse(logs, logs.size());
    }

    /**
     * Accions d'administració.
     *
     * GET /api/audit/logs/admin-actions
     */
    @GET
    @Path("/logs/admin-actions")
    @RolesAllowed("ADMIN")
    public LogsResponse getAdminActions() {
        LOG.debug("Fetching admin actions");

        var logs = auditLogRepository.findAdminActions();

        return new LogsResponse(logs, logs.size());
    }

    /**
     * Verificar integritat de la cadena de logs.
     *
     * POST /api/audit/verify-integrity
     *
     * Resposta:
     * {
     *   "valid": true,
     *   "totalLogs": 12345,
     *   "message": "La cadena de logs és íntegra"
     * }
     *
     * o
     *
     * {
     *   "valid": false,
     *   "totalLogs": 12345,
     *   "message": "ALERTA: Manipulació detectada"
     * }
     */
    @POST
    @Path("/verify-integrity")
    @RolesAllowed("ADMIN")
    public IntegrityResponse verifyIntegrity() {
        LOG.info("Starting audit log integrity verification");

        boolean isValid = auditService.verifyIntegrity();
        long totalLogs = auditLogRepository.count();

        String message = isValid
            ? "La cadena de logs és íntegra. Cap manipulació detectada."
            : "ALERTA: Manipulació detectada a la cadena de logs!";

        return new IntegrityResponse(isValid, totalLogs, message);
    }

    // DTOs

    public static class LogsResponse {
        public List<AuditLog> logs;
        public int total;

        public LogsResponse(List<AuditLog> logs, int total) {
            this.logs = logs;
            this.total = total;
        }
    }

    public static class IntegrityResponse {
        public boolean valid;
        public long totalLogs;
        public String message;

        public IntegrityResponse(boolean valid, long totalLogs, String message) {
            this.valid = valid;
            this.totalLogs = totalLogs;
            this.message = message;
        }
    }
}
