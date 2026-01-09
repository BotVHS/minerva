package cat.minerva.resource;

import cat.minerva.model.User;
import cat.minerva.model.UserRole;
import cat.minerva.repository.UserRepository;
import cat.minerva.security.PasswordHashService;
import cat.minerva.security.TokenService;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import jakarta.inject.Inject;
import org.junit.jupiter.api.*;

import java.time.Instant;
import java.util.Set;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Tests d'integració per UserResource.
 *
 * Verifica:
 * - Creació del primer admin (setup)
 * - Creació d'usuaris nous
 * - Llistat d'usuaris
 * - Actualització d'usuaris
 * - Desactivació d'usuaris
 * - Validacions de dades
 * - Control d'accés per rols
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("User Resource Integration Tests")
class UserResourceIT {

    @Inject
    UserRepository userRepository;

    @Inject
    PasswordHashService passwordHashService;

    @Inject
    TokenService tokenService;

    private static User adminUser;
    private static User analystUser;
    private static String adminToken;
    private static String analystToken;

    @BeforeEach
    void setUp() {
        // Clean up test users
        userRepository.findByUsername("testadmin").ifPresent(user -> userRepository.delete(user));
        userRepository.findByUsername("testanalyst").ifPresent(user -> userRepository.delete(user));
        userRepository.findByUsername("newsupervisor").ifPresent(user -> userRepository.delete(user));
    }

    @AfterEach
    void tearDown() {
        // Clean up after tests
        userRepository.findByUsername("testadmin").ifPresent(user -> userRepository.delete(user));
        userRepository.findByUsername("testanalyst").ifPresent(user -> userRepository.delete(user));
        userRepository.findByUsername("newsupervisor").ifPresent(user -> userRepository.delete(user));
    }

    @Test
    @Order(1)
    @DisplayName("Should create first admin user successfully")
    void testCreateFirstAdmin() {
        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "testadmin",
                    "password": "AdminP@ssw0rd123!",
                    "email": "admin@test.com",
                    "fullName": "Test Admin User"
                }
                """)
        .when()
            .post("/api/setup/first-admin")
        .then()
            .statusCode(201)
            .body("message", containsString("successfully"))
            .body("username", equalTo("testadmin"))
            .body("totpQRCode", notNullValue())
            .body("totpSecret", notNullValue());

        // Verify user exists in database
        var user = userRepository.findByUsername("testadmin");
        assertTrue(user.isPresent(), "Admin user should exist in database");
        assertTrue(user.get().roles.contains(UserRole.ADMIN), "User should have ADMIN role");
        assertTrue(user.get().twoFactorEnabled, "2FA should be enabled");
    }

    @Test
    @Order(2)
    @DisplayName("Should prevent creating first admin when one already exists")
    void testPreventDuplicateFirstAdmin() {
        // Create first admin
        createTestAdmin();

        // Attempt to create another first admin
        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "anotheradmin",
                    "password": "AdminP@ssw0rd123!",
                    "email": "another@test.com",
                    "fullName": "Another Admin"
                }
                """)
        .when()
            .post("/api/setup/first-admin")
        .then()
            .statusCode(409)
            .body("error", containsString("already exists"));
    }

    @Test
    @Order(3)
    @DisplayName("Should validate password strength on first admin creation")
    void testFirstAdminPasswordValidation() {
        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "testadmin",
                    "password": "weak",
                    "email": "admin@test.com",
                    "fullName": "Test Admin"
                }
                """)
        .when()
            .post("/api/setup/first-admin")
        .then()
            .statusCode(400)
            .body("error", containsStringIgnoringCase("password"));
    }

    @Test
    @Order(4)
    @DisplayName("Should validate email format on user creation")
    void testEmailValidation() {
        given()
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "testadmin",
                    "password": "AdminP@ssw0rd123!",
                    "email": "invalid-email",
                    "fullName": "Test Admin"
                }
                """)
        .when()
            .post("/api/setup/first-admin")
        .then()
            .statusCode(400)
            .body("error", containsStringIgnoringCase("email"));
    }

    @Test
    @Order(5)
    @DisplayName("Should require authentication to list users")
    void testListUsersRequiresAuth() {
        given()
        .when()
            .get("/api/users")
        .then()
            .statusCode(401);
    }

    @Test
    @Order(6)
    @DisplayName("Should list users with valid admin token")
    void testListUsersWithAuth() {
        // Create admin and get token
        createTestAdmin();
        adminToken = tokenService.generateAccessToken(adminUser);

        // Create an analyst user for the list
        createTestAnalyst();

        given()
            .header("Authorization", "Bearer " + adminToken)
        .when()
            .get("/api/users")
        .then()
            .statusCode(200)
            .body("$", hasSize(greaterThanOrEqualTo(1)))
            .body("[0].username", notNullValue())
            .body("[0].passwordHash", nullValue()); // Password hash should NOT be exposed
    }

    @Test
    @Order(7)
    @DisplayName("Should create new user with admin privileges")
    void testCreateNewUser() {
        // Create admin and get token
        createTestAdmin();
        adminToken = tokenService.generateAccessToken(adminUser);

        given()
            .header("Authorization", "Bearer " + adminToken)
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "newsupervisor",
                    "email": "supervisor@test.com",
                    "fullName": "New Supervisor User",
                    "roles": ["SUPERVISOR"]
                }
                """)
        .when()
            .post("/api/users")
        .then()
            .statusCode(201)
            .body("username", equalTo("newsupervisor"))
            .body("temporaryPassword", notNullValue())
            .body("temporaryPassword", hasLength(greaterThanOrEqualTo(16)));

        // Verify user exists in database
        var user = userRepository.findByUsername("newsupervisor");
        assertTrue(user.isPresent(), "New user should exist in database");
        assertTrue(user.get().roles.contains(UserRole.SUPERVISOR), "User should have SUPERVISOR role");
        assertTrue(user.get().passwordResetRequired, "Password reset should be required");
    }

    @Test
    @Order(8)
    @DisplayName("Should prevent non-admin from creating users")
    void testNonAdminCannotCreateUsers() {
        // Create analyst user
        createTestAnalyst();
        analystToken = tokenService.generateAccessToken(analystUser);

        given()
            .header("Authorization", "Bearer " + analystToken)
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "newsupervisor",
                    "email": "supervisor@test.com",
                    "fullName": "New Supervisor",
                    "roles": ["SUPERVISOR"]
                }
                """)
        .when()
            .post("/api/users")
        .then()
            .statusCode(403); // Forbidden
    }

    @Test
    @Order(9)
    @DisplayName("Should prevent duplicate username")
    void testDuplicateUsername() {
        // Create admin and analyst
        createTestAdmin();
        adminToken = tokenService.generateAccessToken(adminUser);
        createTestAnalyst();

        // Try to create user with existing username
        given()
            .header("Authorization", "Bearer " + adminToken)
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "testanalyst",
                    "email": "different@test.com",
                    "fullName": "Different User",
                    "roles": ["ANALISTA"]
                }
                """)
        .when()
            .post("/api/users")
        .then()
            .statusCode(409)
            .body("error", containsString("already exists"));
    }

    @Test
    @Order(10)
    @DisplayName("Should update user successfully")
    void testUpdateUser() {
        // Create admin and analyst
        createTestAdmin();
        adminToken = tokenService.generateAccessToken(adminUser);
        createTestAnalyst();

        String userId = analystUser.id.toString();

        given()
            .header("Authorization", "Bearer " + adminToken)
            .contentType(ContentType.JSON)
            .body("""
                {
                    "fullName": "Updated Analyst Name",
                    "email": "updatedemail@test.com"
                }
                """)
        .when()
            .put("/api/users/" + userId)
        .then()
            .statusCode(200)
            .body("fullName", equalTo("Updated Analyst Name"))
            .body("email", equalTo("updatedemail@test.com"));

        // Verify in database
        var user = userRepository.findById(analystUser.id);
        assertTrue(user.isPresent(), "User should still exist");
        assertEquals("Updated Analyst Name", user.get().fullName);
        assertEquals("updatedemail@test.com", user.get().email);
    }

    @Test
    @Order(11)
    @DisplayName("Should deactivate user")
    void testDeactivateUser() {
        // Create admin and analyst
        createTestAdmin();
        adminToken = tokenService.generateAccessToken(adminUser);
        createTestAnalyst();

        String userId = analystUser.id.toString();

        // Deactivate user
        given()
            .header("Authorization", "Bearer " + adminToken)
        .when()
            .delete("/api/users/" + userId)
        .then()
            .statusCode(204); // No content

        // Verify user is deactivated
        var user = userRepository.findById(analystUser.id);
        assertTrue(user.isPresent(), "User should still exist");
        assertFalse(user.get().active, "User should be deactivated");
    }

    @Test
    @Order(12)
    @DisplayName("Should prevent user from deactivating themselves")
    void testCannotDeactivateSelf() {
        // Create admin
        createTestAdmin();
        adminToken = tokenService.generateAccessToken(adminUser);

        String adminId = adminUser.id.toString();

        // Try to deactivate self
        given()
            .header("Authorization", "Bearer " + adminToken)
        .when()
            .delete("/api/users/" + adminId)
        .then()
            .statusCode(400)
            .body("error", containsString("cannot deactivate yourself"));
    }

    @Test
    @Order(13)
    @DisplayName("Should get user by ID")
    void testGetUserById() {
        // Create admin and analyst
        createTestAdmin();
        adminToken = tokenService.generateAccessToken(adminUser);
        createTestAnalyst();

        String userId = analystUser.id.toString();

        given()
            .header("Authorization", "Bearer " + adminToken)
        .when()
            .get("/api/users/" + userId)
        .then()
            .statusCode(200)
            .body("username", equalTo("testanalyst"))
            .body("email", equalTo("analyst@test.com"))
            .body("passwordHash", nullValue()); // Should not expose password hash
    }

    @Test
    @Order(14)
    @DisplayName("Should return 404 for non-existent user")
    void testGetNonExistentUser() {
        // Create admin
        createTestAdmin();
        adminToken = tokenService.generateAccessToken(adminUser);

        given()
            .header("Authorization", "Bearer " + adminToken)
        .when()
            .get("/api/users/507f1f77bcf86cd799439011") // Valid ObjectId but doesn't exist
        .then()
            .statusCode(404);
    }

    @Test
    @Order(15)
    @DisplayName("Should validate role assignment")
    void testInvalidRoleAssignment() {
        // Create admin
        createTestAdmin();
        adminToken = tokenService.generateAccessToken(adminUser);

        given()
            .header("Authorization", "Bearer " + adminToken)
            .contentType(ContentType.JSON)
            .body("""
                {
                    "username": "newsupervisor",
                    "email": "supervisor@test.com",
                    "fullName": "New Supervisor",
                    "roles": ["INVALID_ROLE"]
                }
                """)
        .when()
            .post("/api/users")
        .then()
            .statusCode(400);
    }

    // ========== HELPER METHODS ==========

    private void createTestAdmin() {
        adminUser = new User();
        adminUser.username = "testadmin";
        adminUser.email = "admin@test.com";
        adminUser.fullName = "Test Admin";
        adminUser.passwordHash = passwordHashService.hashPassword("AdminP@ssw0rd123!");
        adminUser.roles = Set.of(UserRole.ADMIN);
        adminUser.active = true;
        adminUser.twoFactorEnabled = false;
        adminUser.createdAt = Instant.now();
        adminUser.updatedAt = Instant.now();

        userRepository.persist(adminUser);
    }

    private void createTestAnalyst() {
        analystUser = new User();
        analystUser.username = "testanalyst";
        analystUser.email = "analyst@test.com";
        analystUser.fullName = "Test Analyst";
        analystUser.passwordHash = passwordHashService.hashPassword("AnalystP@ssw0rd123!");
        analystUser.roles = Set.of(UserRole.ANALISTA);
        analystUser.active = true;
        analystUser.twoFactorEnabled = false;
        analystUser.createdAt = Instant.now();
        analystUser.updatedAt = Instant.now();

        userRepository.persist(analystUser);
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void assertFalse(boolean condition, String message) {
        if (condition) {
            throw new AssertionError(message);
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected " + expected + " but got " + actual);
        }
    }
}
