export enum UserRole {
  ADMIN = 'ADMIN',
  SUPERVISOR = 'SUPERVISOR',
  ANALISTA = 'ANALISTA',
  CONTRIBUIDOR = 'CONTRIBUIDOR'
}

export interface User {
  id: string;
  username: string;
  email: string;
  fullName: string;
  roles: UserRole[];
  active: boolean;
  twoFactorEnabled: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
  lastLoginIp?: string;
  failedLoginAttempts: number;
  lockedUntil?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginPhase1Response {
  pending2FA: boolean;
  sessionToken: string;
  userId: string;
}

export interface Verify2FARequest {
  userId: string;
  sessionToken: string;
  totpCode: string;
}

export interface LoginSuccessResponse {
  accessToken: string;
  refreshToken: string;
  user: User;
}

export interface CreateUserRequest {
  username: string;
  email: string;
  fullName: string;
  password: string;
  roles: UserRole[];
}

export interface CreateUserResponse {
  user: User;
  temporaryPassword: string;
}

export interface UpdateUserRequest {
  email?: string;
  fullName?: string;
  password?: string;
  roles?: UserRole[];
  active?: boolean;
}
