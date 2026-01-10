import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse
} from '@angular/common/http';
import { Observable, throwError, BehaviorSubject } from 'rxjs';
import { catchError, switchMap, filter, take } from 'rxjs/operators';
import { AuthService } from '../../auth/services/auth.service';
import { Router } from '@angular/router';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private isRefreshing = false;
  private refreshTokenSubject: BehaviorSubject<string | null> = new BehaviorSubject<string | null>(null);

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    // Skip adding token to auth endpoints
    const isAuthEndpoint = request.url.includes('/auth/login') ||
                          request.url.includes('/auth/verify-2fa') ||
                          request.url.includes('/auth/logout') ||
                          request.url.includes('/auth/refresh');

    // Add access token to request if available and not an auth endpoint
    const accessToken = this.authService.getAccessToken();

    console.log('[Interceptor] Request:', request.url, 'isAuthEndpoint:', isAuthEndpoint, 'hasToken:', !!accessToken);

    if (accessToken && !isAuthEndpoint) {
      request = this.addToken(request, accessToken);
      console.log('[Interceptor] Token added to request');
    } else if (!accessToken && !isAuthEndpoint) {
      console.warn('[Interceptor] No token available for non-auth endpoint:', request.url);
    }

    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        console.log('[Interceptor] Error:', error.status, 'for', request.url);
        // Only try to refresh if it's a 401 and not an auth request
        if (error.status === 401 && !isAuthEndpoint) {
          console.log('[Interceptor] Attempting token refresh...');
          return this.handle401Error(request, next);
        }

        return throwError(() => error);
      })
    );
  }

  private addToken(request: HttpRequest<any>, token: string): HttpRequest<any> {
    return request.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  private handle401Error(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (!this.isRefreshing) {
      this.isRefreshing = true;
      this.refreshTokenSubject.next(null);

      return this.authService.refreshToken().pipe(
        switchMap(response => {
          this.isRefreshing = false;
          this.refreshTokenSubject.next(response.accessToken);
          // Retry the original request with the new token
          return next.handle(this.addToken(request, response.accessToken));
        }),
        catchError(error => {
          this.isRefreshing = false;
          this.refreshTokenSubject.next(null);
          // Refresh failed, clear tokens and redirect to login
          // Don't call logout() endpoint as it will also trigger 401
          this.authService.clearTokensAndRedirect();
          this.router.navigate(['/login']);
          return throwError(() => error);
        })
      );
    } else {
      // Wait for token refresh to complete
      return this.refreshTokenSubject.pipe(
        filter(token => token !== null),
        take(1),
        switchMap(token => {
          return next.handle(this.addToken(request, token!));
        })
      );
    }
  }
}
