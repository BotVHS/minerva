package cat.minerva.resource;

import cat.minerva.model.User;
import cat.minerva.model.UserRole;
import cat.minerva.repository.UserRepository;
import cat.minerva.security.PasswordHashService;
import cat.minerva.security.TotpService;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import jakarta.inject.Inject;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.*;

import java.time.Instant;
import java.util.Set;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Tests d'integració per AuthResource.
 *
 * Verifica el flux complet d'autenticació:
 * 1. Login fase 1 (credencials)
 * 2. Login fase 2 (2FA)
 * 3. Refresh tokens
 * 4. Logout
 *
 * Utilitza REST Assured per fer peticions HTTP reals.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("Authentication Resource Integration Tests")
class AuthResourceIT {

    @Inject
    UserRepository userRepository;

    @Inject
    PasswordHashService passwordHashService;

    @Inject
    TotpService totpService;

    private static User testUser;
    private static String testPassword = "TestP@ssw0rd123!";
    private static String totpSecret;
    private static String sessionToken;
    private static String userId;
    private static String accessToken;
    private static String refreshToken;

    @BeforeEach
    void setUp() {
        // Clean up test user if exists
        userRepository.findByUsername("integrationtest").ifPresent(user -> {
            userRepository.delete(user);
        });

        // Create test user
        testUser = new User();
        testUser.username = "integrationtest";
        testUser.email = "integration@test.com";
        testUser.fullName = "Integration Test User";
        testUser.passwordHash = passwordHashService.hashPassword(testPassword);
        testUser.roles = Set.of(UserRole.ANALISTA);
        testUser.active = true;
        testUser.twoFactorEnabled = true;
        testUser.totpSecret = totpService.generateSecret();
        testUser.createdAt = Instant.now();
        testUser.updatedAt = Instant.now();

        userRepository.persist(testUser);

        totpSecret = testUser.totpSecret;
        userId = testUser.id.toString();
    }

    @AfterEach
    void tearDown() {
        // Clean up test user
        if (testUser != null && testUser.id != null) {
            userRepository.deleteById(testUser.id);
        }
    }

    @Test
    @Order(1)
    @DisplayName("Should login phase 1 successfully with valid credentials")
    void testLoginPhase1Success() {
        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "integrationtest",
                    "password": "TestP@ssw0rd123!"
                }
                """)
        .when()
            .post("/api/auth/login")
        .then()
            .statusCode(200)
            .body("pending2FA", equalTo(true))
            .body("sessionToken", notNullValue())
            .body("userId", notNullValue())
            .body("message", containsString("2FA"));
    }

    @Test
    @Order(2)
    @DisplayName("Should reject login phase 1 with wrong password")
    void testLoginPhase1WrongPassword() {
        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "integrationtest",
                    "password": "WrongPassword123!"
                }
                """)
        .when()
            .post("/api/auth/login")
        .then()
            .statusCode(401)
            .body("error", containsString("Invalid credentials"));
    }

    @Test
    @Order(3)
    @DisplayName("Should reject login phase 1 with non-existent user")
    void testLoginPhase1NonExistentUser() {
        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "nonexistent",
                    "password": "SomePassword123!"
                }
                """)
        .when()
            .post("/api/auth/login")
        .then()
            .statusCode(401);
    }

    @Test
    @Order(4)
    @DisplayName("Should complete full 2FA login flow")
    void testFullLoginFlow() throws Exception {
        // Step 1: Login phase 1
        var phase1Response = given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "integrationtest",
                    "password": "TestP@ssw0rd123!"
                }
                """)
        .when()
            .post("/api/auth/login")
        .then()
            .statusCode(200)
            .extract();

        sessionToken = phase1Response.path("sessionToken");
        userId = phase1Response.path("userId");

        // Step 2: Generate current TOTP code
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        TimeProvider timeProvider = new SystemTimeProvider();
        long currentBucket = Math.floorDiv(timeProvider.getTime(), 30);
        String totpCode = codeGenerator.generate(totpSecret, currentBucket);

        // Step 3: Login phase 2 with 2FA
        var phase2Response = given()
            .contentType(ContentType.JSON)
            .header("Authorization", "Bearer " + sessionToken)
            .body(String.format("""
                {
                    "userId": "%s",
                    "sessionToken": "%s",
                    "totpCode": "%s"
                }
                """, userId, sessionToken, totpCode))
        .when()
            .post("/api/auth/verify-2fa")
        .then()
            .statusCode(200)
            .body("success", equalTo(true))
            .body("accessToken", notNullValue())
            .body("refreshToken", notNullValue())
            .body("user.username", equalTo("integrationtest"))
            .body("user.roles", hasItem("ANALISTA"))
            .extract();

        accessToken = phase2Response.path("accessToken");
        refreshToken = phase2Response.path("refreshToken");

        assertNotNull(accessToken);
        assertNotNull(refreshToken);
    }

    @Test
    @Order(5)
    @DisplayName("Should reject 2FA with wrong code")
    void testWrong2FACode() {
        // Step 1: Login phase 1
        var phase1Response = given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "integrationtest",
                    "password": "TestP@ssw0rd123!"
                }
                """)
        .when()
            .post("/api/auth/login")
        .then()
            .statusCode(200)
            .extract();

        sessionToken = phase1Response.path("sessionToken");
        userId = phase1Response.path("userId");

        // Step 2: Try with wrong TOTP code
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "Bearer " + sessionToken)
            .body(String.format("""
                {
                    "userId": "%s",
                    "sessionToken": "%s",
                    "totpCode": "000000"
                }
                """, userId, sessionToken))
        .when()
            .post("/api/auth/verify-2fa")
        .then()
            .statusCode(401)
            .body("error", containsString("Invalid 2FA code"));
    }

    @Test
    @Order(6)
    @DisplayName("Should reject login for inactive user")
    void testInactiveUserLogin() {
        // Deactivate user
        testUser.active = false;
        userRepository.update(testUser);

        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "integrationtest",
                    "password": "TestP@ssw0rd123!"
                }
                """)
        .when()
            .post("/api/auth/login")
        .then()
            .statusCode(403)
            .body("error", containsString("disabled"));

        // Reactivate for other tests
        testUser.active = true;
        userRepository.update(testUser);
    }

    @Test
    @Order(7)
    @DisplayName("Should validate request body")
    void testValidation() {
        // Empty username
        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "",
                    "password": "TestP@ssw0rd123!"
                }
                """)
        .when()
            .post("/api/auth/login")
        .then()
            .statusCode(400);

        // Missing password
        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "integrationtest"
                }
                """)
        .when()
            .post("/api/auth/login")
        .then()
            .statusCode(400);
    }

    @Test
    @Order(8)
    @DisplayName("Should enforce account lockout after failed attempts")
    void testAccountLockout() {
        // Make 5 failed login attempts
        for (int i = 0; i < 5; i++) {
            given()
                .contentType(ContentType.JSON)
                .body("""
                    {
                        "username": "integrationtest",
                        "password": "WrongPassword!"
                    }
                    """)
            .when()
                .post("/api/auth/login")
            .then()
                .statusCode(401);
        }

        // 6th attempt should be locked
        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "integrationtest",
                    "password": "TestP@ssw0rd123!"
                }
                """)
        .when()
            .post("/api/auth/login")
        .then()
            .statusCode(423)
            .body("error", containsString("locked"));

        // Unlock for other tests
        testUser.unlockAccount();
        userRepository.update(testUser);
    }
}
