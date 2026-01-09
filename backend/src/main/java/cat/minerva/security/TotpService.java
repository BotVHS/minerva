package cat.minerva.security;

import com.bastiaanjansen.otp.SecretGenerator;
import com.bastiaanjansen.otp.TOTP;
import com.bastiaanjansen.otp.TOTPGenerator;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
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

    // Paràmetres TOTP (RFC 6238)
    private static final Duration PERIOD = Duration.ofSeconds(30);  // Període de 30 segons
    private static final int DIGITS = 6;  // Codis de 6 dígits
    private static final int SECRET_SIZE = 160;  // 160 bits de secret

    @ConfigProperty(name = "minerva.security.totp.issuer", defaultValue = "Minerva Gov")
    String issuer;

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
            byte[] secret = SecretGenerator.generate(SECRET_SIZE);
            String base32Secret = Base64.getEncoder().encodeToString(secret);
            LOG.debug("Generated new TOTP secret");
            return base32Secret;
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
            // Construir la URI otpauth
            String uri = String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
                URLEncoder.encode(issuer, StandardCharsets.UTF_8),
                URLEncoder.encode(username, StandardCharsets.UTF_8),
                secret,
                URLEncoder.encode(issuer, StandardCharsets.UTF_8),
                DIGITS,
                PERIOD.getSeconds()
            );

            // Generar QR code
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(uri, BarcodeFormat.QR_CODE, 300, 300);

            // Convertir a imatge PNG
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);

            // Retornar com Base64 per enviar al client
            String base64Image = Base64.getEncoder().encodeToString(outputStream.toByteArray());
            LOG.debugf("Generated QR code for user: %s", username);

            return base64Image;
        } catch (Exception e) {
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
        if (code == null || code.length() != DIGITS) {
            LOG.debug("Invalid TOTP code format");
            return false;
        }

        try {
            // Decodificar el secret de Base64
            byte[] secretBytes = Base64.getDecoder().decode(secret);

            // Crear generador TOTP
            TOTPGenerator totpGenerator = new TOTPGenerator.Builder(secretBytes)
                .withPeriod(PERIOD)
                .withPasswordLength(DIGITS)
                .build();

            // Crear instància TOTP
            TOTP totp = new TOTP.Builder(totpGenerator)
                .build();

            // Validar amb finestra de temps (±1 període = 90 segons total)
            // Això compensa petites diferències de rellotge
            boolean isValid = totp.verify(code, 1);

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
            byte[] secretBytes = Base64.getDecoder().decode(secret);

            TOTPGenerator totpGenerator = new TOTPGenerator.Builder(secretBytes)
                .withPeriod(PERIOD)
                .withPasswordLength(DIGITS)
                .build();

            String code = totpGenerator.now();
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

        try {
            byte[] decoded = Base64.getDecoder().decode(secret);
            // El secret ha de tenir almenys 128 bits (16 bytes)
            return decoded.length >= 16;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Calcula el temps restant fins al proper canvi de codi.
     *
     * Útil per mostrar al client quan expirarà el codi actual.
     *
     * @return segons restants fins al proper codi
     */
    public long getSecondsUntilNextCode() {
        long currentTime = System.currentTimeMillis() / 1000;
        long period = PERIOD.getSeconds();
        return period - (currentTime % period);
    }
}
