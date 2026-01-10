import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot, UrlTree } from '@angular/router';
import { Observable } from 'rxjs';
import { AuthService } from '../../auth/services/auth.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard {
  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean | UrlTree> | Promise<boolean | UrlTree> | boolean | UrlTree {
    if (this.authService.isAuthenticated()) {
      // Check if route requires specific role
      const requiredRoles = route.data['roles'] as Array<string>;

      if (requiredRoles) {
        const hasRequiredRole = requiredRoles.some(role =>
          this.authService.hasRole(role)
        );

        if (!hasRequiredRole) {
          // User doesn't have required role, redirect to dashboard
          return this.router.createUrlTree(['/dashboard']);
        }
      }

      return true;
    }

    // Not authenticated, redirect to login
    return this.router.createUrlTree(['/login'], {
      queryParams: { returnUrl: state.url }
    });
  }
}
