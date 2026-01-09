package cat.minerva.dto.response;

import cat.minerva.model.User;
import cat.minerva.model.UserRole;

import java.time.Instant;
import java.util.Set;

/**
 * DTO per representar un usuari en les respostes (sense dades sensibles).
 */
public class UserDTO {

    public String id;
    public String username;
    public String email;
    public String fullName;
    public Set<UserRole> roles;
    public boolean active;
    public boolean twoFactorEnabled;
    public Instant lastLoginAt;
    public Instant createdAt;

    public static UserDTO from(User user) {
        if (user == null) {
            return null;
        }

        UserDTO dto = new UserDTO();
        dto.id = user.id != null ? user.id.toString() : null;
        dto.username = user.username;
        dto.email = user.email;
        dto.fullName = user.fullName;
        dto.roles = user.roles;
        dto.active = user.active;
        dto.twoFactorEnabled = user.twoFactorEnabled;
        dto.lastLoginAt = user.lastLoginAt;
        dto.createdAt = user.createdAt;
        return dto;
    }
}
