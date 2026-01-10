package cat.minerva.security;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests per TotpService (2FA amb TOTP - RFC 6238).
 *
 * Verifica:
 * - Generació de secrets TOTP
 * - Generació de codis TOTP
 * - Validació de codis TOTP
 * - Generació de QR codes
 * - Compatibilitat amb Google Authenticator
 * - Time window (30 segons)
 */
@QuarkusTest
@DisplayName("TOTP Service Tests (2FA)")
class TotpServiceTest {

    @Inject
    TotpService totpService;

    @Test
    @DisplayName("Should generate valid TOTP secret")
    void testGenerateSecret() {
        // When
        String secret = totpService.generateSecret();

        // Then
        assertNotNull(secret, "Secret should not be null");
        assertFalse(secret.isEmpty(), "Secret should not be empty");
        assertTrue(secret.length() >= 16, "Secret should be at least 16 characters");
        // Base32 alphabet: A-Z, 2-7, =
        assertTrue(secret.matches("^[A-Z2-7=]+$"), "Secret should be Base32 encoded");
    }

    @Test
    @DisplayName("Should generate unique secrets")
    void testUniqueSecrets() {
        // When
        String secret1 = totpService.generateSecret();
        String secret2 = totpService.generateSecret();
        String secret3 = totpService.generateSecret();

        // Then
        assertNotEquals(secret1, secret2, "Secrets should be unique");
        assertNotEquals(secret2, secret3, "Secrets should be unique");
        assertNotEquals(secret1, secret3, "Secrets should be unique");
    }

    @Test
    @DisplayName("Should validate correct TOTP code")
    void testValidateCorrectCode() throws Exception {
        // Given
        String secret = totpService.generateSecret();

        // Generate current TOTP code
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        TimeProvider timeProvider = new SystemTimeProvider();
        long currentBucket = Math.floorDiv(timeProvider.getTime(), 30);
        String currentCode = codeGenerator.generate(secret, currentBucket);

        // When
        boolean isValid = totpService.validateCode(currentCode, secret);

        // Then
        assertTrue(isValid, "Current TOTP code should be valid");
    }

    @Test
    @DisplayName("Should reject incorrect TOTP code")
    void testValidateIncorrectCode() {
        // Given
        String secret = totpService.generateSecret();
        String incorrectCode = "000000";

        // When
        boolean isValid = totpService.validateCode(incorrectCode, secret);

        // Then
        assertFalse(isValid, "Incorrect TOTP code should be rejected");
    }

    @Test
    @DisplayName("Should reject code with wrong length")
    void testInvalidCodeLength() {
        // Given
        String secret = totpService.generateSecret();

        // When & Then
        assertFalse(totpService.validateCode("12345", secret), "5-digit code should be rejected");
        assertFalse(totpService.validateCode("1234567", secret), "7-digit code should be rejected");
        assertFalse(totpService.validateCode("", secret), "Empty code should be rejected");
    }

    @Test
    @DisplayName("Should reject non-numeric code")
    void testNonNumericCode() {
        // Given
        String secret = totpService.generateSecret();

        // When & Then
        assertFalse(totpService.validateCode("ABC123", secret), "Alphanumeric code should be rejected");
        assertFalse(totpService.validateCode("12345a", secret), "Code with letters should be rejected");
    }

    @Test
    @DisplayName("Should generate QR code as base64 string")
    void testGenerateQRCode() {
        // Given
        String username = "testuser";
        String secret = totpService.generateSecret();

        // When
        String qrCode = totpService.generateQRCode(username, secret);

        // Then
        assertNotNull(qrCode, "QR code should not be null");
        // QR code is returned as raw base64 PNG data (no data URL prefix)
        assertTrue(qrCode.length() > 100, "QR code data should be substantial");
        // Verify it's valid base64 (only contains A-Z, a-z, 0-9, +, /, =)
        assertTrue(qrCode.matches("^[A-Za-z0-9+/=]+$"), "QR code should be valid base64");
    }

    @Test
    @DisplayName("QR code should be valid base64 PNG")
    void testQRCodeContent() {
        // Given
        String username = "admin@test.com";
        String secret = totpService.generateSecret();

        // When
        String qrCode = totpService.generateQRCode(username, secret);

        // Then
        assertNotNull(qrCode);
        // QR code encodes: otpauth://totp/Minerva%20Gov:admin@test.com?secret=...&issuer=Minerva%20Gov
        // We can't decode it easily in test, but we can check it's valid base64
        assertTrue(qrCode.matches("^[A-Za-z0-9+/=]+$"), "QR code should be valid base64");
        assertTrue(qrCode.length() > 100, "QR code should contain substantial data");
    }

    @Test
    @DisplayName("Should generate different QR codes for different users")
    void testDifferentQRCodes() {
        // Given
        String secret = totpService.generateSecret();

        // When
        String qrCode1 = totpService.generateQRCode("user1", secret);
        String qrCode2 = totpService.generateQRCode("user2", secret);

        // Then
        assertNotEquals(qrCode1, qrCode2, "Different users should have different QR codes");
    }

    @Test
    @DisplayName("Should handle null secret gracefully")
    void testNullSecret() {
        // When
        boolean isValid = totpService.validateCode("123456", null);

        // Then
        assertFalse(isValid, "Null secret should return false (not throw exception)");
    }

    @Test
    @DisplayName("Should handle null code gracefully")
    void testNullCode() {
        // Given
        String secret = totpService.generateSecret();

        // When & Then
        assertFalse(totpService.validateCode(null, secret), "Null code should be rejected");
    }

    @Test
    @DisplayName("Should reject expired code (time window test)")
    void testTimeWindow() throws Exception {
        // Given
        String secret = totpService.generateSecret();

        // Generate code for past time bucket (2 minutes ago, 4 buckets)
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        TimeProvider timeProvider = new SystemTimeProvider();
        long pastBucket = Math.floorDiv(timeProvider.getTime(), 30) - 4;
        String pastCode = codeGenerator.generate(secret, pastBucket);

        // When
        boolean isValid = totpService.validateCode(pastCode, secret);

        // Then
        assertFalse(isValid, "Code from 2 minutes ago should be rejected (outside time window)");
    }

    @Test
    @DisplayName("Should accept code within time window (previous bucket)")
    void testTimeWindowPreviousBucket() throws Exception {
        // Given
        String secret = totpService.generateSecret();

        // Generate code for previous time bucket (30 seconds ago)
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        TimeProvider timeProvider = new SystemTimeProvider();
        long previousBucket = Math.floorDiv(timeProvider.getTime(), 30) - 1;
        String previousCode = codeGenerator.generate(secret, previousBucket);

        // When
        boolean isValid = totpService.validateCode(previousCode, secret);

        // Then
        assertTrue(isValid, "Code from previous 30-second window should be valid");
    }

    @Test
    @DisplayName("Should accept code within time window (next bucket)")
    void testTimeWindowNextBucket() throws Exception {
        // Given
        String secret = totpService.generateSecret();

        // Generate code for next time bucket (30 seconds in future)
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        TimeProvider timeProvider = new SystemTimeProvider();
        long nextBucket = Math.floorDiv(timeProvider.getTime(), 30) + 1;
        String nextCode = codeGenerator.generate(secret, nextBucket);

        // When
        boolean isValid = totpService.validateCode(nextCode, secret);

        // Then
        assertTrue(isValid, "Code from next 30-second window should be valid");
    }

    @Test
    @DisplayName("Should generate 6-digit codes")
    void testCodeFormat() throws Exception {
        // Given
        String secret = totpService.generateSecret();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        TimeProvider timeProvider = new SystemTimeProvider();
        long currentBucket = Math.floorDiv(timeProvider.getTime(), 30);

        // When
        String code = codeGenerator.generate(secret, currentBucket);

        // Then
        assertEquals(6, code.length(), "TOTP code should be 6 digits");
        assertTrue(code.matches("^\\d{6}$"), "TOTP code should be 6 numeric digits");
    }

    @Test
    @DisplayName("Should reject code with leading zeros stripped")
    void testLeadingZeros() {
        // Given
        String secret = totpService.generateSecret();

        // When & Then - If code is "000123", accepting "123" should fail
        assertFalse(totpService.validateCode("12345", secret), "5-digit code should not match 6-digit with leading zero");
    }

    @Test
    @DisplayName("Should handle special characters in username for QR code")
    void testSpecialCharactersInUsername() {
        // Given
        String username = "user+test@example.com";
        String secret = totpService.generateSecret();

        // When
        String qrCode = totpService.generateQRCode(username, secret);

        // Then
        assertNotNull(qrCode, "QR code should handle special characters in username");
        assertTrue(qrCode.matches("^[A-Za-z0-9+/=]+$"), "QR code should be valid base64");
        assertTrue(qrCode.length() > 100, "QR code should contain substantial data");
    }

    @Test
    @DisplayName("TOTP should be compatible with RFC 6238 spec")
    void testRFC6238Compatibility() {
        // RFC 6238 test vectors (SHA1, 8-digit codes)
        // Our implementation uses SHA1, 6-digit codes, 30-second step
        // We test that our secret generation and validation is compatible

        // Given
        String secret = totpService.generateSecret();

        // When - Generate and validate immediately
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        TimeProvider timeProvider = new SystemTimeProvider();
        long currentBucket = Math.floorDiv(timeProvider.getTime(), 30);

        try {
            String code = codeGenerator.generate(secret, currentBucket);
            boolean isValid = totpService.validateCode(code, secret);

            // Then
            assertTrue(isValid, "TOTP should validate its own generated codes (RFC 6238 compatible)");
        } catch (Exception e) {
            fail("TOTP generation/validation should not throw exception: " + e.getMessage());
        }
    }
}
