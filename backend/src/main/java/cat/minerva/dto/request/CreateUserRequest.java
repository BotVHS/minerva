package cat.minerva.dto.request;

import cat.minerva.model.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.Set;

/**
 * DTO per crear un nou usuari (només administradors).
 */
public class CreateUserRequest {

    @NotBlank(message = "Username is required")
    public String username;

    @Email(message = "Email must be valid")
    public String email;

    public String fullName;

    @NotNull(message = "At least one role is required")
    public Set<UserRole> roles;
}
