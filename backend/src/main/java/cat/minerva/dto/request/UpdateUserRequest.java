package cat.minerva.dto.request;

import cat.minerva.model.UserRole;
import jakarta.validation.constraints.Email;

import java.util.Set;

/**
 * DTO per actualitzar un usuari existent (només administradors).
 *
 * Tots els camps són opcionals - només s'actualitzaran els camps proporcionats.
 */
public class UpdateUserRequest {

    @Email(message = "Email must be valid")
    public String email;

    public String fullName;

    public Set<UserRole> roles;

    public Boolean active;
}
