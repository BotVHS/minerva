package cat.minerva.security;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.util.regex.Pattern;

/**
 * Servei per hashing i validació de contrasenyes amb Argon2id.
 *
 * Argon2id és l'algoritme recomanat per OWASP per hashing de contrasenyes:
 * - Guanyador del Password Hashing Competition (2015)
 * - Resistent a atacs GPU i ASIC
 * - Protecció contra side-channel attacks
 * - Combina Argon2i (protecció contra timing attacks) i Argon2d (protecció contra GPU cracking)
 *
 * Paràmetres utilitzats:
 * - Type: Argon2id (variant híbrida més segura)
 * - Iterations: 3 (t_cost) - balanç entre seguretat i rendiment
 * - Memory: 65536 KB (64 MB) - dificultat per atacs paral·lels
 * - Parallelism: 4 threads
 * - Salt: generat automàticament de forma aleatòria per cada contrasenya
 *
 * El hash generat inclou tots els paràmetres i el salt:
 * Format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
 */
@ApplicationScoped
public class PasswordHashService {

    private static final Logger LOG = Logger.getLogger(PasswordHashService.class);

    // Paràmetres de configuració Argon2
    private static final int ITERATIONS = 3;        // Nombre d'iteracions
    private static final int MEMORY = 65536;        // Memòria en KB (64 MB)
    private static final int PARALLELISM = 4;       // Nombre de threads

    // Política de contrasenyes
    @ConfigProperty(name = "minerva.security.password.min-length", defaultValue = "12")
    int minLength;

    @ConfigProperty(name = "minerva.security.password.require-uppercase", defaultValue = "true")
    boolean requireUppercase;

    @ConfigProperty(name = "minerva.security.password.require-lowercase", defaultValue = "true")
    boolean requireLowercase;

    @ConfigProperty(name = "minerva.security.password.require-digit", defaultValue = "true")
    boolean requireDigit;

    @ConfigProperty(name = "minerva.security.password.require-special", defaultValue = "true")
    boolean requireSpecial;

    private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

    /**
     * Genera un hash segur d'una contrasenya utilitzant Argon2id.
     *
     * El salt es genera automàticament de forma aleatòria.
     * El hash resultant inclou el salt i tots els paràmetres.
     *
     * @param password contrasenya en text pla
     * @return hash de la contrasenya (inclou salt i paràmetres)
     */
    public String hashPassword(String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }

        try {
            // Generar hash amb Argon2id
            // El mètode hash() genera automàticament un salt aleatori
            String hash = argon2.hash(ITERATIONS, MEMORY, PARALLELISM, password.toCharArray());
            LOG.debugf("Password hashed successfully");
            return hash;
        } catch (Exception e) {
            LOG.error("Error hashing password", e);
            throw new RuntimeException("Failed to hash password", e);
        }
    }

    /**
     * Verifica una contrasenya contra el seu hash.
     *
     * @param password contrasenya en text pla
     * @param hash hash emmagatzemat (inclou salt i paràmetres)
     * @return true si la contrasenya coincideix, false altrament
     */
    public boolean verifyPassword(String password, String hash) {
        if (password == null || hash == null) {
            return false;
        }

        try {
            boolean matches = argon2.verify(hash, password.toCharArray());
            LOG.debugf("Password verification: %s", matches ? "SUCCESS" : "FAILED");
            return matches;
        } catch (Exception e) {
            LOG.error("Error verifying password", e);
            return false;
        }
    }

    /**
     * Valida una contrasenya segons la política de seguretat.
     *
     * La política requereix (configurable):
     * - Mínim 12 caràcters
     * - Almenys una majúscula
     * - Almenys una minúscula
     * - Almenys un dígit
     * - Almenys un caràcter especial
     *
     * @param password contrasenya a validar
     * @return missatge d'error si no compleix la política, null si és vàlida
     */
    public String validatePassword(String password) {
        if (password == null || password.isEmpty()) {
            return "La contrasenya no pot estar buida";
        }

        if (password.length() < minLength) {
            return String.format("La contrasenya ha de tenir almenys %d caràcters", minLength);
        }

        if (requireUppercase && !Pattern.compile("[A-Z]").matcher(password).find()) {
            return "La contrasenya ha de contenir almenys una lletra majúscula";
        }

        if (requireLowercase && !Pattern.compile("[a-z]").matcher(password).find()) {
            return "La contrasenya ha de contenir almenys una lletra minúscula";
        }

        if (requireDigit && !Pattern.compile("[0-9]").matcher(password).find()) {
            return "La contrasenya ha de contenir almenys un dígit";
        }

        if (requireSpecial && !Pattern.compile("[^A-Za-z0-9]").matcher(password).find()) {
            return "La contrasenya ha de contenir almenys un caràcter especial";
        }

        // Comprovacions addicionals de seguretat
        if (isCommonPassword(password)) {
            return "Aquesta contrasenya és massa comuna i no és segura";
        }

        return null; // Contrasenya vàlida
    }

    /**
     * Comprova si una contrasenya és massa comuna.
     *
     * En producció, això hauria de consultar una llista de contrasenyes
     * compromeses (com Have I Been Pwned).
     * Aquí només comprovem alguns casos obvics.
     *
     * @param password contrasenya a comprovar
     * @return true si és massa comuna
     */
    private boolean isCommonPassword(String password) {
        String lower = password.toLowerCase();

        // Llista de contrasenyes comunes (simplificada)
        String[] commonPasswords = {
            "password", "password123", "123456", "123456789", "qwerty",
            "abc123", "password1", "admin", "letmein", "welcome",
            "monkey", "dragon", "master", "sunshine", "princess"
        };

        for (String common : commonPasswords) {
            if (lower.equals(common) || lower.contains(common)) {
                return true;
            }
        }

        // Comprovar patrons repetitius
        if (Pattern.compile("(.)\\1{2,}").matcher(password).find()) {
            // 3+ caràcters consecutius iguals (ex: "aaa", "111")
            return true;
        }

        // Comprovar seqüències (ex: "123", "abc")
        if (password.contains("123") || password.contains("abc") ||
            password.contains("qwerty") || password.contains("asdf")) {
            return true;
        }

        return false;
    }

    /**
     * Genera una contrasenya temporal aleatòria que compleix la política.
     *
     * Utilitzat per crear contrasenyes temporals en creació d'usuaris.
     * L'usuari hauria de canviar-la en el primer login.
     *
     * @return contrasenya temporal
     */
    public String generateTemporaryPassword() {
        String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowercase = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String special = "!@#$%^&*()-_=+[]{}|;:,.<>?";

        StringBuilder password = new StringBuilder();
        java.security.SecureRandom random = new java.security.SecureRandom();

        // Assegurar que té almenys un de cada tipus
        password.append(uppercase.charAt(random.nextInt(uppercase.length())));
        password.append(lowercase.charAt(random.nextInt(lowercase.length())));
        password.append(digits.charAt(random.nextInt(digits.length())));
        password.append(special.charAt(random.nextInt(special.length())));

        // Afegir caràcters aleatoris fins arribar a la longitud mínima + 4
        String allChars = uppercase + lowercase + digits + special;
        for (int i = 4; i < minLength + 4; i++) {
            password.append(allChars.charAt(random.nextInt(allChars.length())));
        }

        // Barrejar els caràcters
        char[] chars = password.toString().toCharArray();
        for (int i = chars.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = chars[i];
            chars[i] = chars[j];
            chars[j] = temp;
        }

        return new String(chars);
    }

    /**
     * Neteja la instància d'Argon2 (allibera memòria nativa).
     * Hauria de cridar-se en shutdown de l'aplicació.
     */
    public void cleanup() {
        argon2.wipeArray(new char[0]); // Cleanup
    }
}
