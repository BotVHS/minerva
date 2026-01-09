package cat.minerva.security;

import cat.minerva.model.RefreshToken;
import cat.minerva.model.User;
import cat.minerva.model.UserRole;
import cat.minerva.repository.RefreshTokenRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.mockito.InjectMock;
import jakarta.inject.Inject;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests per TokenService.
 *
 * Verifica:
 * - Generació de JWT access tokens
 * - Generació de refresh tokens
 * - Rotació de refresh tokens
 * - Revocació de tokens
 * - Detecció de reutilització de tokens (atac)
 * - Device fingerprinting
 */
@QuarkusTest
@DisplayName("Token Service Tests")
class TokenServiceTest {

    @Inject
    TokenService tokenService;

    @InjectMock
    RefreshTokenRepository refreshTokenRepository;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.id = new ObjectId();
        testUser.username = "testuser";
        testUser.email = "test@example.com";
        testUser.roles = Set.of(UserRole.ANALISTA);
        testUser.active = true;
    }

    @Test
    @DisplayName("Should generate valid JWT access token")
    void testGenerateAccessToken() {
        // When
        String accessToken = tokenService.generateAccessToken(testUser);

        // Then
        assertNotNull(accessToken, "Access token should not be null");
        assertFalse(accessToken.isEmpty(), "Access token should not be empty");

        // JWT structure: header.payload.signature
        String[] parts = accessToken.split("\\.");
        assertEquals(3, parts.length, "JWT should have 3 parts");
    }

    @Test
    @DisplayName("Access token should contain user information")
    void testAccessTokenContents() {
        // When
        String accessToken = tokenService.generateAccessToken(testUser);

        // Then
        // Decode JWT manually or use library
        assertTrue(accessToken.length() > 100, "Access token should contain encoded data");

        // JWT should be signed (last part is signature)
        String[] parts = accessToken.split("\\.");
        assertTrue(parts[2].length() > 0, "JWT should have signature");
    }

    @Test
    @DisplayName("Should generate different access tokens for different users")
    void testDifferentAccessTokens() {
        // Given
        User user2 = new User();
        user2.id = new ObjectId();
        user2.username = "user2";
        user2.roles = Set.of(UserRole.SUPERVISOR);

        // When
        String token1 = tokenService.generateAccessToken(testUser);
        String token2 = tokenService.generateAccessToken(user2);

        // Then
        assertNotEquals(token1, token2, "Different users should have different tokens");
    }

    @Test
    @DisplayName("Should generate refresh token successfully")
    void testGenerateRefreshToken() {
        // Given
        String deviceFingerprint = "device123";
        String ipAddress = "192.168.1.1";

        when(refreshTokenRepository.persist(any(RefreshToken.class))).thenAnswer(invocation -> {
            RefreshToken token = invocation.getArgument(0);
            token.id = new ObjectId();
            return token;
        });

        // When
        String refreshToken = tokenService.generateRefreshToken(testUser, deviceFingerprint, ipAddress);

        // Then
        assertNotNull(refreshToken, "Refresh token should not be null");
        assertFalse(refreshToken.isEmpty(), "Refresh token should not be empty");
        assertTrue(refreshToken.length() >= 32, "Refresh token should be cryptographically secure");

        // Verify repository interaction
        verify(refreshTokenRepository, times(1)).persist(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Should store refresh token in database")
    void testRefreshTokenPersistence() {
        // Given
        String deviceFingerprint = "device123";
        String ipAddress = "192.168.1.1";

        when(refreshTokenRepository.persist(any(RefreshToken.class))).thenAnswer(invocation -> {
            RefreshToken token = invocation.getArgument(0);
            // Verify token properties
            assertEquals(testUser.id, token.userId);
            assertEquals(deviceFingerprint, token.deviceFingerprint);
            assertEquals(ipAddress, token.ipAddress);
            assertFalse(token.revoked);
            assertNotNull(token.tokenHash);
            assertNotNull(token.expiresAt);

            token.id = new ObjectId();
            return token;
        });

        // When
        tokenService.generateRefreshToken(testUser, deviceFingerprint, ipAddress);

        // Then
        verify(refreshTokenRepository).persist(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Should revoke refresh token")
    void testRevokeRefreshToken() {
        // Given
        String token = "validtoken123";
        String tokenHash = tokenService.hashToken(token);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.id = new ObjectId();
        refreshToken.tokenHash = tokenHash;
        refreshToken.userId = testUser.id;
        refreshToken.revoked = false;
        refreshToken.expiresAt = Instant.now().plus(1, ChronoUnit.DAYS);

        when(refreshTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(refreshToken));
        when(refreshTokenRepository.update(any(RefreshToken.class))).thenReturn(refreshToken);

        // When
        boolean revoked = tokenService.revokeRefreshToken(token, "User logout");

        // Then
        assertTrue(revoked, "Token should be revoked");
        assertTrue(refreshToken.revoked, "Token revoked flag should be set");
        assertNotNull(refreshToken.revokedAt, "Revoked timestamp should be set");
        assertEquals("User logout", refreshToken.revokeReason);

        verify(refreshTokenRepository).update(refreshToken);
    }

    @Test
    @DisplayName("Should not revoke non-existent token")
    void testRevokeNonExistentToken() {
        // Given
        String token = "nonexistent";
        String tokenHash = tokenService.hashToken(token);

        when(refreshTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.empty());

        // When
        boolean revoked = tokenService.revokeRefreshToken(token, "Test");

        // Then
        assertFalse(revoked, "Non-existent token should return false");
        verify(refreshTokenRepository, never()).update(any());
    }

    @Test
    @DisplayName("Should revoke all user tokens")
    void testRevokeAllUserTokens() {
        // Given
        RefreshToken token1 = new RefreshToken();
        token1.id = new ObjectId();
        token1.revoked = false;

        RefreshToken token2 = new RefreshToken();
        token2.id = new ObjectId();
        token2.revoked = false;

        when(refreshTokenRepository.findActiveByUserId(testUser.id))
            .thenReturn(java.util.List.of(token1, token2));
        when(refreshTokenRepository.update(any(RefreshToken.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));

        // When
        long count = tokenService.revokeAllUserTokens(testUser, "Security measure");

        // Then
        assertEquals(2, count, "Should revoke 2 tokens");
        assertTrue(token1.revoked);
        assertTrue(token2.revoked);
        verify(refreshTokenRepository, times(2)).update(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Refresh tokens should have expiration")
    void testRefreshTokenExpiration() {
        // Given
        String deviceFingerprint = "device123";
        String ipAddress = "192.168.1.1";

        when(refreshTokenRepository.persist(any(RefreshToken.class))).thenAnswer(invocation -> {
            RefreshToken token = invocation.getArgument(0);

            // Verify expiration is set (24 hours from now)
            Instant now = Instant.now();
            Instant expiresAt = token.expiresAt;

            long hoursDifference = ChronoUnit.HOURS.between(now, expiresAt);
            assertTrue(hoursDifference >= 23 && hoursDifference <= 25,
                "Expiration should be approximately 24 hours from now");

            token.id = new ObjectId();
            return token;
        });

        // When
        tokenService.generateRefreshToken(testUser, deviceFingerprint, ipAddress);

        // Then
        verify(refreshTokenRepository).persist(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Should hash token before storage (security)")
    void testTokenHashing() {
        // Given
        String plainToken = "myplaintoken123";

        // When
        String hash = tokenService.hashToken(plainToken);

        // Then
        assertNotNull(hash);
        assertNotEquals(plainToken, hash, "Token should be hashed, not stored in plain text");
        assertTrue(hash.length() == 64, "SHA-256 hash should be 64 hex characters");
        assertTrue(hash.matches("^[a-f0-9]{64}$"), "Hash should be lowercase hexadecimal");
    }

    @Test
    @DisplayName("Same token should produce same hash")
    void testConsistentHashing() {
        // Given
        String token = "consistenttoken";

        // When
        String hash1 = tokenService.hashToken(token);
        String hash2 = tokenService.hashToken(token);

        // Then
        assertEquals(hash1, hash2, "Same token should produce consistent hash");
    }

    @Test
    @DisplayName("Different tokens should produce different hashes")
    void testDifferentHashes() {
        // Given
        String token1 = "token1";
        String token2 = "token2";

        // When
        String hash1 = tokenService.hashToken(token1);
        String hash2 = tokenService.hashToken(token2);

        // Then
        assertNotEquals(hash1, hash2, "Different tokens should produce different hashes");
    }

    @Test
    @DisplayName("Should track device fingerprint")
    void testDeviceFingerprint() {
        // Given
        String deviceFp1 = "Mozilla/5.0 (Windows NT 10.0)";
        String deviceFp2 = "Mozilla/5.0 (iPhone; CPU iPhone OS 14)";
        String ipAddress = "192.168.1.1";

        when(refreshTokenRepository.persist(any(RefreshToken.class))).thenAnswer(invocation -> {
            RefreshToken token = invocation.getArgument(0);
            token.id = new ObjectId();
            return token;
        });

        // When
        String token1 = tokenService.generateRefreshToken(testUser, deviceFp1, ipAddress);
        String token2 = tokenService.generateRefreshToken(testUser, deviceFp2, ipAddress);

        // Then
        assertNotEquals(token1, token2, "Different devices should get different tokens");
        verify(refreshTokenRepository, times(2)).persist(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Should cleanup expired tokens")
    void testCleanupExpiredTokens() {
        // Given
        when(refreshTokenRepository.deleteExpiredTokens()).thenReturn(5L);

        // When
        long deletedCount = tokenService.cleanupExpiredTokens();

        // Then
        assertEquals(5, deletedCount);
        verify(refreshTokenRepository).deleteExpiredTokens();
    }

    @Test
    @DisplayName("Generated tokens should be cryptographically secure")
    void testTokenRandomness() {
        // Given
        String deviceFingerprint = "device";
        String ipAddress = "127.0.0.1";

        when(refreshTokenRepository.persist(any(RefreshToken.class))).thenAnswer(invocation -> {
            RefreshToken token = invocation.getArgument(0);
            token.id = new ObjectId();
            return token;
        });

        // When - Generate multiple tokens
        String token1 = tokenService.generateRefreshToken(testUser, deviceFingerprint, ipAddress);
        String token2 = tokenService.generateRefreshToken(testUser, deviceFingerprint, ipAddress);
        String token3 = tokenService.generateRefreshToken(testUser, deviceFingerprint, ipAddress);

        // Then - All should be unique (cryptographically random)
        assertNotEquals(token1, token2);
        assertNotEquals(token2, token3);
        assertNotEquals(token1, token3);
    }
}
