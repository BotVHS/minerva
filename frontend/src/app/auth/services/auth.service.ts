import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import {
  LoginRequest,
  LoginPhase1Response,
  Verify2FARequest,
  LoginSuccessResponse,
  User
} from '../../shared/models/user.model';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly API_URL = '/api/auth';
  private readonly TOKEN_KEY = 'minerva_access_token';
  private readonly REFRESH_TOKEN_KEY = 'minerva_refresh_token';

  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  constructor(private http: HttpClient) {
    this.loadUserFromToken();
  }

  /**
   * Login fase 1: Credencials
   */
  loginPhase1(credentials: LoginRequest): Observable<LoginPhase1Response> {
    return this.http.post<LoginPhase1Response>(`${this.API_URL}/login`, credentials);
  }

  /**
   * Login fase 2: Verificació 2FA
   */
  verify2FA(request: Verify2FARequest): Observable<LoginSuccessResponse> {
    return this.http.post<LoginSuccessResponse>(`${this.API_URL}/verify-2fa`, request)
      .pipe(
        tap(response => {
          this.storeTokens(response.accessToken, response.refreshToken);
          this.currentUserSubject.next(response.user);
        })
      );
  }

  /**
   * Logout
   */
  logout(): Observable<void> {
    return this.http.post<void>(`${this.API_URL}/logout`, {})
      .pipe(
        tap(() => {
          this.clearTokens();
          this.currentUserSubject.next(null);
        })
      );
  }

  /**
   * Refresh access token
   */
  refreshToken(): Observable<{ accessToken: string; refreshToken: string }> {
    const refreshToken = this.getRefreshToken();
    return this.http.post<{ accessToken: string; refreshToken: string }>(
      `${this.API_URL}/refresh`,
      { refreshToken }
    ).pipe(
      tap(response => {
        this.storeTokens(response.accessToken, response.refreshToken);
      })
    );
  }

  /**
   * Get current user
   */
  getCurrentUser(): User | null {
    return this.currentUserSubject.value;
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return this.getAccessToken() !== null;
  }

  /**
   * Check if user has specific role
   */
  hasRole(role: string): boolean {
    const user = this.getCurrentUser();
    return user?.roles.includes(role as any) ?? false;
  }

  /**
   * Check if user is admin
   */
  isAdmin(): boolean {
    return this.hasRole('ADMIN');
  }

  /**
   * Get access token
   */
  getAccessToken(): string | null {
    return sessionStorage.getItem(this.TOKEN_KEY);
  }

  /**
   * Get refresh token
   */
  getRefreshToken(): string | null {
    return sessionStorage.getItem(this.REFRESH_TOKEN_KEY);
  }

  /**
   * Store tokens
   */
  private storeTokens(accessToken: string, refreshToken: string): void {
    sessionStorage.setItem(this.TOKEN_KEY, accessToken);
    sessionStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
  }

  /**
   * Clear tokens
   */
  private clearTokens(): void {
    sessionStorage.removeItem(this.TOKEN_KEY);
    sessionStorage.removeItem(this.REFRESH_TOKEN_KEY);
  }

  /**
   * Clear tokens and user session (public method for interceptor)
   */
  clearTokensAndRedirect(): void {
    this.clearTokens();
    this.currentUserSubject.next(null);
  }

  /**
   * Load user from token (decode JWT)
   */
  private loadUserFromToken(): void {
    const token = this.getAccessToken();
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        // You would normally fetch the full user details from the server
        // For now, we'll create a minimal user object
        const user: User = {
          id: payload.sub,
          username: payload.upn || payload.preferred_username,
          email: '',
          fullName: '',
          roles: payload.groups || [],
          active: true,
          twoFactorEnabled: true,
          createdAt: '',
          updatedAt: '',
          failedLoginAttempts: 0
        };
        this.currentUserSubject.next(user);
      } catch (error) {
        console.error('Error parsing token:', error);
        this.clearTokens();
      }
    }
  }
}
