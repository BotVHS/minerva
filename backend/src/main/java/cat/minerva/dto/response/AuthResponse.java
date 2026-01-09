package cat.minerva.dto.response;

/**
 * DTO per respostes d'autenticació.
 */
public class AuthResponse {

    public boolean success;
    public boolean pending2FA;
    public String message;
    public String sessionToken;
    public String accessToken;
    public String refreshToken;
    public String userId;
    public UserDTO user;

    public static AuthResponse success(String accessToken, String refreshToken, UserDTO user) {
        AuthResponse response = new AuthResponse();
        response.success = true;
        response.accessToken = accessToken;
        response.refreshToken = refreshToken;
        response.user = user;
        return response;
    }

    public static AuthResponse pending2FA(String sessionToken, String userId) {
        AuthResponse response = new AuthResponse();
        response.pending2FA = true;
        response.sessionToken = sessionToken;
        response.userId = userId;
        response.message = "Introdueix el codi 2FA";
        return response;
    }

    public static AuthResponse failed(String message) {
        AuthResponse response = new AuthResponse();
        response.success = false;
        response.message = message;
        return response;
    }
}
