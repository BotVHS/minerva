package cat.minerva.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * DTO per la petició de login (Fase 1).
 */
public class LoginRequest {

    @NotBlank(message = "Username is required")
    public String username;

    @NotBlank(message = "Password is required")
    public String password;
}
