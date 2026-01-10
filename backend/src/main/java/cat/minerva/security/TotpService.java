package cat.minerva.security;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Servei per gestionar TOTP (Time-based One-Time Password) per 2FA.
 *
 * Implementa RFC 6238: TOTP (Time-Based One-Time Password Algorithm)
 * Compatible amb apps d'autenticació estàndard:
 * - Google Authenticator
 * - Authy
 * - Microsoft Authenticator
 * - 1Password
 * - Etc.
 *
 * Funcionament:
 * 1. Es genera un secret aleatori (Base32) per cada usuari
 * 2. El secret es mostra una sola vegada via QR code
 * 3. L'usuari escaneja el QR amb la seva app d'autenticació
 * 4. L'app genera codis de 6 dígits cada 30 segons
 * 5. L'usuari introdueix el codi per validar el 2FA
 *
 * Seguretat:
 * - Secret de 160 bits (alta entropia)
 * - Finestra de validació de ±1 període (90 segons total) per clock skew
 * - Cada codi només és vàlid 30 segons
 * - El secret mai es mostra després de la configuració inicial
 */
@ApplicationScoped
public class TotpService {

    private static final Logger LOG = Logger.getLogger(TotpService.class);

    @ConfigProperty(name = "minerva.security.totp.issuer", defaultValue = "Minerva")
    String issuer;

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    /**
     * Genera un nou secret TOTP per un usuari.
     *
     * El secret és una cadena Base32 de 160 bits.
     * Aquest secret s'ha de guardar xifrat a la base de dades.
     *
     * @return secret TOTP en format Base32
     */
    public String generateSecret() {
        try {
            String secret = secretGenerator.generate();
            LOG.debug("Generated new TOTP secret");
            return secret;
        } catch (Exception e) {
            LOG.error("Error generating TOTP secret", e);
            throw new RuntimeException("Failed to generate TOTP secret", e);
        }
    }

    /**
     * Genera un QR code per configurar el 2FA.
     *
     * El QR conté una URI del format:
     * otpauth://totp/Issuer:username?secret=SECRET&issuer=Issuer&digits=6&period=30
     *
     * @param username nom d'usuari
     * @param secret secret TOTP en Base32
     * @return imatge PNG del QR code en Base64
     */
    public String generateQRCode(String username, String secret) {
        try {
            QrData data = new QrData.Builder()
                .label(username)
                .secret(secret)
                .issuer(issuer)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

            byte[] imageData = qrGenerator.generate(data);
            String base64Image = Base64.getEncoder().encodeToString(imageData);

            LOG.debugf("Generated QR code for user: %s", username);
            return base64Image;

        } catch (QrGenerationException e) {
            LOG.error("Error generating QR code", e);
            throw new RuntimeException("Failed to generate QR code", e);
        }
    }

    /**
     * Valida un codi TOTP.
     *
     * Accepta codis dins d'una finestra de ±1 període (90 segons total)
     * per compensar diferències de rellotge entre client i servidor.
     *
     * @param code codi de 6 dígits introduït per l'usuari
     * @param secret secret TOTP de l'usuari (Base32)
     * @return true si el codi és vàlid, false altrament
     */
    public boolean validateCode(String code, String secret) {
        if (code == null || code.length() != 6) {
            LOG.debug("Invalid TOTP code format");
            return false;
        }

        try {
            // Validar amb finestra de temps (±1 període = 90 segons total)
            boolean isValid = verifier.isValidCode(secret, code);

            LOG.debugf("TOTP validation: %s", isValid ? "SUCCESS" : "FAILED");
            return isValid;

        } catch (Exception e) {
            LOG.error("Error validating TOTP code", e);
            return false;
        }
    }

    /**
     * Genera el codi TOTP actual per un secret.
     *
     * NOMÉS per testing/debugging. En producció, el codi es genera
     * a l'app del client, no al servidor.
     *
     * @param secret secret TOTP (Base32)
     * @return codi de 6 dígits actual
     */
    public String getCurrentCode(String secret) {
        try {
            long currentBucket = Math.floorDiv(timeProvider.getTime(), 30);
            String code = codeGenerator.generate(secret, currentBucket);
            LOG.debug("Generated current TOTP code (for testing only)");
            return code;

        } catch (Exception e) {
            LOG.error("Error generating current TOTP code", e);
            throw new RuntimeException("Failed to generate TOTP code", e);
        }
    }

    /**
     * Valida el format d'un secret TOTP.
     *
     * @param secret secret a validar
     * @return true si el format és vàlid
     */
    public boolean isValidSecret(String secret) {
        if (secret == null || secret.isEmpty()) {
            return false;
        }

        // El secret ha de ser Base32 (A-Z, 2-7, =)
        return secret.matches("^[A-Z2-7=]+$") && secret.length() >= 16;
    }

    /**
     * Calcula el temps restant fins al proper canvi de codi.
     *
     * Útil per mostrar al client quan expirarà el codi actual.
     *
     * @return segons restants fins al proper codi
     */
    public long getSecondsUntilNextCode() {
        long currentTime = timeProvider.getTime();
        long period = 30;
        return period - (currentTime % period);
    }
}
