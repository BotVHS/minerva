package cat.minerva.model;

/**
 * Tipus d'accions que es registren en els logs d'auditoria.
 *
 * Totes les accions crítiques del sistema queden registrades
 * de forma immutable per complir amb els requisits d'auditoria governamental.
 */
public enum AuditAction {
    // Autenticació
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    LOGOUT,

    // 2FA
    TWO_FA_SETUP,
    TWO_FA_ENABLED,
    TWO_FA_DISABLED,
    TWO_FA_SUCCESS,
    TWO_FA_FAILED,
    TWO_FA_RESET,

    // Gestió d'usuaris
    USER_CREATED,
    USER_UPDATED,
    USER_DISABLED,
    USER_ENABLED,
    USER_DELETED,

    // Gestió de rols
    ROLE_ASSIGNED,
    ROLE_REMOVED,

    // Gestió de contrasenyes
    PASSWORD_CHANGED,
    PASSWORD_RESET_REQUESTED,
    PASSWORD_RESET_COMPLETED,

    // Tokens
    TOKEN_REFRESHED,
    TOKEN_REVOKED,

    // Intents sospitosos
    ACCOUNT_LOCKED,
    ACCOUNT_UNLOCKED,
    SUSPICIOUS_ACTIVITY_DETECTED,
    RATE_LIMIT_EXCEEDED,

    // Accés a recursos sensibles
    SENSITIVE_DATA_ACCESSED,
    AUDIT_LOG_ACCESSED,

    // Sistema
    SYSTEM_CONFIGURATION_CHANGED
}
