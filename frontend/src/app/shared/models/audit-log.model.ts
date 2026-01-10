export enum AuditAction {
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  LOGOUT = 'LOGOUT',
  USER_CREATED = 'USER_CREATED',
  USER_UPDATED = 'USER_UPDATED',
  USER_DELETED = 'USER_DELETED',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  TWO_FA_ENABLED = 'TWO_FA_ENABLED',
  TWO_FA_DISABLED = 'TWO_FA_DISABLED',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED'
}

export interface AuditLog {
  id: string;
  timestamp: string;
  userId?: string;
  username?: string;
  action: AuditAction;
  ipAddress: string;
  userAgent?: string;
  details?: string;
  success: boolean;
  previousHash?: string;
  currentHash: string;
}
