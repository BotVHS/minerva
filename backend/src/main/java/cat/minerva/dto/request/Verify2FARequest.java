package cat.minerva.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * DTO per validar el codi 2FA (Fase 2).
 */
public class Verify2FARequest {

    @NotBlank(message = "User ID is required")
    public String userId;

    @NotBlank(message = "TOTP code is required")
    @Pattern(regexp = "^[0-9]{6}$", message = "TOTP code must be 6 digits")
    public String totpCode;
}
