package cat.minerva.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * DTO per renovar tokens amb refresh token.
 */
public class RefreshTokenRequest {

    @NotBlank(message = "Refresh token is required")
    public String refreshToken;
}
