package cat.minerva.repository;

import cat.minerva.model.AuditAction;
import cat.minerva.model.AuditLog;
import io.quarkus.mongodb.panache.PanacheMongoRepository;
import io.quarkus.panache.common.Sort;
import jakarta.enterprise.context.ApplicationScoped;
import org.bson.types.ObjectId;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repositori per gestionar logs d'auditoria immutables.
 *
 * Important: aquesta col·lecció és append-only.
 * Mai s'ha de modificar o eliminar cap entrada (excepte per manteniment autoritzat).
 *
 * La integritat de la cadena de hashs es pot verificar periòdicament
 * per detectar qualsevol manipulació.
 */
@ApplicationScoped
public class AuditLogRepository implements PanacheMongoRepository<AuditLog> {

    /**
     * Obté l'últim log de la cadena.
     * Utilitzat per obtenir el previousHash quan es crea un nou log.
     *
     * @return Optional amb l'últim log
     */
    public Optional<AuditLog> findLatest() {
        return findAll(Sort.descending("sequenceNumber")).firstResultOptional();
    }

    /**
     * Obté el següent número de seqüència.
     *
     * @return proper número de seqüència
     */
    public long getNextSequenceNumber() {
        return findLatest()
                .map(log -> log.sequenceNumber + 1)
                .orElse(1L);
    }

    /**
     * Troba tots els logs d'un usuari específic.
     *
     * @param userId ID de l'usuari
     * @return llista de logs de l'usuari
     */
    public List<AuditLog> findByUserId(ObjectId userId) {
        return list("userId", Sort.descending("timestamp"), userId);
    }

    /**
     * Troba tots els logs d'un usuari en un rang de dates.
     *
     * @param userId ID de l'usuari
     * @param from data inicial
     * @param to data final
     * @return llista de logs
     */
    public List<AuditLog> findByUserIdAndDateRange(ObjectId userId, Instant from, Instant to) {
        return list("userId = ?1 and timestamp >= ?2 and timestamp <= ?3",
                    Sort.descending("timestamp"), userId, from, to);
    }

    /**
     * Troba tots els logs d'una acció específica.
     *
     * @param action tipus d'acció
     * @return llista de logs de l'acció
     */
    public List<AuditLog> findByAction(AuditAction action) {
        return list("action", Sort.descending("timestamp"), action);
    }

    /**
     * Troba tots els intents de login fallits.
     *
     * @return llista de login fallits
     */
    public List<AuditLog> findFailedLogins() {
        return list("action = ?1 and success = false",
                    Sort.descending("timestamp"), AuditAction.LOGIN_FAILED);
    }

    /**
     * Troba intents de login fallits des d'una IP específica.
     *
     * @param ipAddress IP a filtrar
     * @param since timestamp mínim
     * @return llista de login fallits
     */
    public List<AuditLog> findFailedLoginsByIp(String ipAddress, Instant since) {
        return list("action = ?1 and success = false and ipAddress = ?2 and timestamp > ?3",
                    Sort.descending("timestamp"),
                    AuditAction.LOGIN_FAILED, ipAddress, since);
    }

    /**
     * Troba tots els logs d'accions d'administració.
     *
     * @return llista de logs d'administració
     */
    public List<AuditLog> findAdminActions() {
        return list("action in ?1", Sort.descending("timestamp"),
                    List.of(AuditAction.USER_CREATED, AuditAction.USER_UPDATED,
                           AuditAction.USER_DISABLED, AuditAction.ROLE_ASSIGNED));
    }

    /**
     * Troba logs per rang de dates.
     *
     * @param from data inicial
     * @param to data final
     * @return llista de logs
     */
    public List<AuditLog> findByDateRange(Instant from, Instant to) {
        return list("timestamp >= ?1 and timestamp <= ?2",
                    Sort.descending("timestamp"), from, to);
    }

    /**
     * Troba logs d'activitat sospitosa.
     *
     * @return llista de logs sospitosos
     */
    public List<AuditLog> findSuspiciousActivity() {
        return list("action in ?1", Sort.descending("timestamp"),
                    List.of(AuditAction.SUSPICIOUS_ACTIVITY_DETECTED,
                           AuditAction.ACCOUNT_LOCKED,
                           AuditAction.RATE_LIMIT_EXCEEDED));
    }

    /**
     * Verifica la integritat de tota la cadena de logs.
     *
     * Recorre tots els logs en ordre i comprova que els hashs coincideixin.
     *
     * @return true si la cadena és íntegra, false si s'ha detectat manipulació
     */
    public boolean verifyChainIntegrity() {
        List<AuditLog> logs = listAll(Sort.ascending("sequenceNumber"));

        if (logs.isEmpty()) {
            return true;
        }

        String expectedPreviousHash = "";
        for (AuditLog log : logs) {
            if (!log.verifyIntegrity(expectedPreviousHash)) {
                return false;
            }
            expectedPreviousHash = log.currentHash;
        }

        return true;
    }

    /**
     * Verifica la integritat d'un rang de logs.
     *
     * @param fromSequence número de seqüència inicial
     * @param toSequence número de seqüència final
     * @return true si el rang és íntegre
     */
    public boolean verifyChainIntegrityRange(long fromSequence, long toSequence) {
        List<AuditLog> logs = list("sequenceNumber >= ?1 and sequenceNumber <= ?2",
                                   Sort.ascending("sequenceNumber"),
                                   fromSequence, toSequence);

        if (logs.isEmpty()) {
            return true;
        }

        // Obtenir el hash anterior al primer log del rang
        String expectedPreviousHash = "";
        if (fromSequence > 1) {
            Optional<AuditLog> previousLog = find("sequenceNumber", fromSequence - 1).firstResultOptional();
            if (previousLog.isPresent()) {
                expectedPreviousHash = previousLog.get().currentHash;
            }
        }

        for (AuditLog log : logs) {
            if (!log.verifyIntegrity(expectedPreviousHash)) {
                return false;
            }
            expectedPreviousHash = log.currentHash;
        }

        return true;
    }

    /**
     * Troba logs no verificats.
     *
     * @return llista de logs pendents de verificació
     */
    public List<AuditLog> findUnverified() {
        return list("verified = false", Sort.ascending("sequenceNumber"));
    }

    /**
     * Cerca logs per text lliure (username, details, etc.).
     *
     * @param searchTerm terme de cerca
     * @return llista de logs que coincideixen
     */
    public List<AuditLog> search(String searchTerm) {
        return list("username like ?1 or details like ?1",
                    Sort.descending("timestamp"), "%" + searchTerm + "%");
    }
}
