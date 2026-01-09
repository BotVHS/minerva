package cat.minerva.repository;

import cat.minerva.model.User;
import cat.minerva.model.UserRole;
import io.quarkus.mongodb.panache.PanacheMongoRepository;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Optional;

/**
 * Repositori per gestionar usuaris a MongoDB.
 *
 * Proporciona mètodes per trobar usuaris per diferents criteris
 * i operacions específiques de seguretat.
 */
@ApplicationScoped
public class UserRepository implements PanacheMongoRepository<User> {

    /**
     * Troba un usuari pel seu nom d'usuari.
     *
     * @param username nom d'usuari
     * @return Optional amb l'usuari si existeix
     */
    public Optional<User> findByUsername(String username) {
        return find("username", username).firstResultOptional();
    }

    /**
     * Troba un usuari per email.
     *
     * @param email email de l'usuari
     * @return Optional amb l'usuari si existeix
     */
    public Optional<User> findByEmail(String email) {
        return find("email", email).firstResultOptional();
    }

    /**
     * Comprova si existeix un usuari amb un nom d'usuari determinat.
     *
     * @param username nom d'usuari a comprovar
     * @return true si existeix, false altrament
     */
    public boolean existsByUsername(String username) {
        return count("username", username) > 0;
    }

    /**
     * Troba tots els usuaris actius amb un rol específic.
     *
     * @param role rol a filtrar
     * @return llista d'usuaris amb el rol especificat
     */
    public java.util.List<User> findActiveByRole(UserRole role) {
        return list("active = true and roles", role);
    }

    /**
     * Troba tots els usuaris actius.
     *
     * @return llista d'usuaris actius
     */
    public java.util.List<User> findAllActive() {
        return list("active", true);
    }

    /**
     * Troba tots els usuaris amb bloqueig actiu.
     *
     * @return llista d'usuaris bloquejats
     */
    public java.util.List<User> findLockedUsers() {
        return list("lockedUntil != null and lockedUntil > ?1", java.time.Instant.now());
    }

    /**
     * Troba usuaris que no han fet login des de fa X dies.
     *
     * @param days nombre de dies d'inactivitat
     * @return llista d'usuaris inactius
     */
    public java.util.List<User> findInactiveUsers(int days) {
        java.time.Instant threshold = java.time.Instant.now().minus(days, java.time.temporal.ChronoUnit.DAYS);
        return list("lastLoginAt < ?1 or lastLoginAt = null", threshold);
    }
}
