package cat.minerva.security;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests per PasswordHashService.
 *
 * Verifica:
 * - Hashing de contrasenyes amb Argon2id
 * - Verificació de contrasenyes
 * - Validació de política de contrasenyes
 * - Generació de contrasenyes temporals
 * - Seguretat contra atacs de força bruta
 */
@QuarkusTest
@DisplayName("Password Hashing Service Tests")
class PasswordHashServiceTest {

    @Inject
    PasswordHashService passwordHashService;

    @Test
    @DisplayName("Should hash password successfully")
    void testHashPassword() {
        // Given
        String password = "MySecureP@ssw0rd!";

        // When
        String hash = passwordHashService.hashPassword(password);

        // Then
        assertNotNull(hash, "Hash should not be null");
        assertTrue(hash.startsWith("$argon2id$"), "Hash should start with $argon2id$");
        assertNotEquals(password, hash, "Hash should be different from plain password");
    }

    @Test
    @DisplayName("Should produce different hashes for same password (salt)")
    void testDifferentSalts() {
        // Given
        String password = "SamePassword123!";

        // When
        String hash1 = passwordHashService.hashPassword(password);
        String hash2 = passwordHashService.hashPassword(password);

        // Then
        assertNotEquals(hash1, hash2, "Two hashes of same password should be different due to unique salts");
    }

    @Test
    @DisplayName("Should verify correct password")
    void testVerifyCorrectPassword() {
        // Given
        String password = "CorrectP@ssw0rd!";
        String hash = passwordHashService.hashPassword(password);

        // When
        boolean isValid = passwordHashService.verifyPassword(password, hash);

        // Then
        assertTrue(isValid, "Correct password should verify successfully");
    }

    @Test
    @DisplayName("Should reject incorrect password")
    void testVerifyIncorrectPassword() {
        // Given
        String correctPassword = "CorrectP@ssw0rd!";
        String incorrectPassword = "WrongPassword123!";
        String hash = passwordHashService.hashPassword(correctPassword);

        // When
        boolean isValid = passwordHashService.verifyPassword(incorrectPassword, hash);

        // Then
        assertFalse(isValid, "Incorrect password should not verify");
    }

    @Test
    @DisplayName("Should reject password with minor modification")
    void testPasswordSensitivity() {
        // Given
        String password = "MyP@ssw0rd!";
        String hash = passwordHashService.hashPassword(password);

        // When & Then - Case sensitivity
        assertFalse(passwordHashService.verifyPassword("myp@ssw0rd!", hash),
            "Password verification should be case-sensitive");

        // When & Then - Extra character
        assertFalse(passwordHashService.verifyPassword(password + "x", hash),
            "Should reject password with extra character");

        // When & Then - Missing character
        assertFalse(passwordHashService.verifyPassword(password.substring(0, password.length() - 1), hash),
            "Should reject password with missing character");
    }

    @Test
    @DisplayName("Should validate strong password")
    void testValidateStrongPassword() {
        // Given
        String strongPassword = "MyV3ryStr0ng!P@ssword";

        // When
        String validationError = passwordHashService.validatePassword(strongPassword);

        // Then
        assertNull(validationError, "Strong password should be valid");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "short",                    // Too short
        "nouppercase123!",          // No uppercase
        "NOLOWERCASE123!",          // No lowercase
        "NoDigits!@#",              // No digits
        "NoSpecialChar123",         // No special characters
        "12345678901",              // Only digits
        "!!!!!!!!!!!!",             // Only special chars
    })
    @DisplayName("Should reject weak passwords")
    void testRejectWeakPasswords(String weakPassword) {
        // When
        String validationError = passwordHashService.validatePassword(weakPassword);

        // Then
        assertNotNull(validationError, "Weak password should be rejected: " + weakPassword);
    }

    @Test
    @DisplayName("Should reject password shorter than 12 characters")
    void testMinimumLength() {
        // Given
        String shortPassword = "Short1!";

        // When
        String validationError = passwordHashService.validatePassword(shortPassword);

        // Then
        assertNotNull(validationError);
        assertTrue(validationError.contains("12"), "Error should mention minimum length");
    }

    @Test
    @DisplayName("Should generate valid temporary password")
    void testGenerateTemporaryPassword() {
        // When
        String tempPassword = passwordHashService.generateTemporaryPassword();

        // Then
        assertNotNull(tempPassword, "Temporary password should not be null");
        assertEquals(16, tempPassword.length(), "Temporary password should be 16 characters");

        // Validate it meets password policy
        String validationError = passwordHashService.validatePassword(tempPassword);
        assertNull(validationError, "Temporary password should meet password policy");
    }

    @Test
    @DisplayName("Should generate unique temporary passwords")
    void testUniqueTemporaryPasswords() {
        // When
        String temp1 = passwordHashService.generateTemporaryPassword();
        String temp2 = passwordHashService.generateTemporaryPassword();
        String temp3 = passwordHashService.generateTemporaryPassword();

        // Then
        assertNotEquals(temp1, temp2, "Temporary passwords should be unique");
        assertNotEquals(temp2, temp3, "Temporary passwords should be unique");
        assertNotEquals(temp1, temp3, "Temporary passwords should be unique");
    }

    @Test
    @DisplayName("Should handle null password gracefully")
    void testNullPassword() {
        // When & Then
        assertThrows(NullPointerException.class,
            () -> passwordHashService.hashPassword(null),
            "Should throw exception for null password");
    }

    @Test
    @DisplayName("Should handle empty password")
    void testEmptyPassword() {
        // When
        String validationError = passwordHashService.validatePassword("");

        // Then
        assertNotNull(validationError, "Empty password should be rejected");
    }

    @Test
    @DisplayName("Should handle very long password")
    void testVeryLongPassword() {
        // Given
        String longPassword = "A".repeat(1000) + "1!";

        // When
        String hash = passwordHashService.hashPassword(longPassword);
        boolean isValid = passwordHashService.verifyPassword(longPassword, hash);

        // Then
        assertNotNull(hash, "Should handle very long passwords");
        assertTrue(isValid, "Should verify very long passwords");
    }

    @Test
    @DisplayName("Password hashing should be resistant to timing attacks")
    void testTimingAttackResistance() {
        // Given
        String password = "MyP@ssw0rd123!";
        String hash = passwordHashService.hashPassword(password);

        // When - Measure verification times
        long startCorrect = System.nanoTime();
        passwordHashService.verifyPassword(password, hash);
        long correctTime = System.nanoTime() - startCorrect;

        long startIncorrect = System.nanoTime();
        passwordHashService.verifyPassword("WrongPassword!", hash);
        long incorrectTime = System.nanoTime() - startIncorrect;

        // Then - Times should be similar (within 50%)
        double ratio = (double) correctTime / incorrectTime;
        assertTrue(ratio > 0.5 && ratio < 2.0,
            "Verification time should be similar for correct and incorrect passwords to prevent timing attacks");
    }

    @Test
    @DisplayName("Should accept password with all allowed special characters")
    void testAllSpecialCharacters() {
        // Given - All common special characters
        String[] specialChars = {"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+", "[", "]", "{", "}", ";", ":", "'", "\"", ",", ".", "<", ">", "/", "?"};

        for (String specialChar : specialChars) {
            String password = "ValidP@ss123" + specialChar;

            // When
            String validationError = passwordHashService.validatePassword(password);

            // Then
            assertNull(validationError,
                "Password with special character '" + specialChar + "' should be valid");
        }
    }

    @Test
    @DisplayName("Should handle Unicode characters")
    void testUnicodeCharacters() {
        // Given
        String unicodePassword = "MyP@ssw0rd123!ñáéíóú";

        // When
        String hash = passwordHashService.hashPassword(unicodePassword);
        boolean isValid = passwordHashService.verifyPassword(unicodePassword, hash);

        // Then
        assertTrue(isValid, "Should handle Unicode characters correctly");
    }
}
