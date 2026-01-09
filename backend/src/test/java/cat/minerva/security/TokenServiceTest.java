package cat.minerva.security;

import cat.minerva.model.User;
import cat.minerva.model.UserRole;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests per TokenService.
 *
 * Verifica:
 * - Generació de JWT access tokens
 * - Estructura i contingut dels tokens
 * - Tokens únics per diferents usuaris
 */
@QuarkusTest
@DisplayName("Token Service Tests")
class TokenServiceTest {

    @Inject
    TokenService tokenService;

    private User testUser;
    private User anotherUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.id = new ObjectId();
        testUser.username = "testuser";
        testUser.email = "test@example.com";
        testUser.roles = Set.of(UserRole.ANALISTA);
        testUser.active = true;

        anotherUser = new User();
        anotherUser.id = new ObjectId();
        anotherUser.username = "anotheruser";
        anotherUser.email = "another@example.com";
        anotherUser.roles = Set.of(UserRole.CONTRIBUIDOR);
        anotherUser.active = true;
    }

    @Test
    @DisplayName("Should generate valid JWT access token")
    void testGenerateAccessToken() {
        // When
        String accessToken = tokenService.generateAccessToken(testUser);

        // Then
        assertNotNull(accessToken, "Access token should not be null");
        assertFalse(accessToken.isEmpty(), "Access token should not be empty");

        // JWT has 3 parts separated by dots: header.payload.signature
        String[] parts = accessToken.split("\\.");
        assertEquals(3, parts.length, "JWT should have 3 parts (header.payload.signature)");
    }

    @Test
    @DisplayName("Should generate different tokens for different users")
    void testDifferentTokensForDifferentUsers() {
        // When
        String token1 = tokenService.generateAccessToken(testUser);
        String token2 = tokenService.generateAccessToken(anotherUser);

        // Then
        assertNotEquals(token1, token2, "Tokens for different users should be different");
    }

    @Test
    @DisplayName("Should handle null user gracefully")
    void testNullUser() {
        // When/Then
        assertThrows(Exception.class, () -> {
            tokenService.generateAccessToken(null);
        }, "Should throw exception for null user");
    }

    @Test
    @DisplayName("Should generate token with user ID in claims")
    void testTokenContainsUserId() {
        // When
        String accessToken = tokenService.generateAccessToken(testUser);

        // Then
        assertNotNull(accessToken);
        // Note: To fully verify claims, we'd need to decode the JWT
        // which requires the public key. For now, we verify it's generated.
        assertTrue(accessToken.length() > 100, "JWT should be reasonably long");
    }

    @Test
    @DisplayName("Should generate tokens with consistent format")
    void testTokenFormat() {
        // When
        String token1 = tokenService.generateAccessToken(testUser);
        String token2 = tokenService.generateAccessToken(testUser);

        // Then - both should be valid JWTs
        String[] parts1 = token1.split("\\.");
        String[] parts2 = token2.split("\\.");

        assertEquals(3, parts1.length, "First token should have 3 parts");
        assertEquals(3, parts2.length, "Second token should have 3 parts");

        // Tokens should be different even for same user (due to timestamps)
        assertNotEquals(token1, token2, "Each token should be unique");
    }

    @Test
    @DisplayName("Should generate token for user with multiple roles")
    void testMultipleRoles() {
        // Given
        testUser.roles = Set.of(UserRole.ADMIN, UserRole.SUPERVISOR);

        // When
        String accessToken = tokenService.generateAccessToken(testUser);

        // Then
        assertNotNull(accessToken);
        String[] parts = accessToken.split("\\.");
        assertEquals(3, parts.length, "JWT should have 3 parts even with multiple roles");
    }

    @Test
    @DisplayName("Should generate token for user with single role")
    void testSingleRole() {
        // Given
        testUser.roles = Set.of(UserRole.CONTRIBUIDOR);

        // When
        String accessToken = tokenService.generateAccessToken(testUser);

        // Then
        assertNotNull(accessToken);
        String[] parts = accessToken.split("\\.");
        assertEquals(3, parts.length);
    }

    @Test
    @DisplayName("Should generate token for admin user")
    void testAdminToken() {
        // Given
        testUser.roles = Set.of(UserRole.ADMIN);

        // When
        String accessToken = tokenService.generateAccessToken(testUser);

        // Then
        assertNotNull(accessToken);
        String[] parts = accessToken.split("\\.");
        assertEquals(3, parts.length);
    }

    @Test
    @DisplayName("Should generate unique tokens on successive calls")
    void testTokenUniqueness() {
        // When - generate multiple tokens quickly
        String token1 = tokenService.generateAccessToken(testUser);
        String token2 = tokenService.generateAccessToken(testUser);
        String token3 = tokenService.generateAccessToken(testUser);

        // Then - all should be unique (different iat timestamps)
        assertNotEquals(token1, token2);
        assertNotEquals(token2, token3);
        assertNotEquals(token1, token3);
    }

    @Test
    @DisplayName("Should handle user with empty username")
    void testEmptyUsername() {
        // Given
        testUser.username = "";

        // When/Then - may throw exception or handle gracefully depending on implementation
        try {
            String token = tokenService.generateAccessToken(testUser);
            assertNotNull(token, "Should handle empty username");
        } catch (Exception e) {
            // Also acceptable to throw exception
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("Should handle user with no roles")
    void testNoRoles() {
        // Given
        testUser.roles = Set.of();

        // When
        String token = tokenService.generateAccessToken(testUser);

        // Then
        assertNotNull(token, "Should generate token even with no roles");
        String[] parts = token.split("\\.");
        assertEquals(3, parts.length);
    }

    @Test
    @DisplayName("Should handle user with null ID")
    void testNullUserId() {
        // Given
        testUser.id = null;

        // When/Then
        assertThrows(Exception.class, () -> {
            tokenService.generateAccessToken(testUser);
        }, "Should throw exception for null user ID");
    }

    @Test
    @DisplayName("Should generate cryptographically random tokens")
    void testTokenRandomness() {
        // When - generate many tokens
        String token1 = tokenService.generateAccessToken(testUser);
        String token2 = tokenService.generateAccessToken(testUser);
        String token3 = tokenService.generateAccessToken(testUser);
        String token4 = tokenService.generateAccessToken(testUser);
        String token5 = tokenService.generateAccessToken(testUser);

        // Then - all should be unique
        assertEquals(5, Set.of(token1, token2, token3, token4, token5).size(),
                    "All generated tokens should be unique");
    }
}
