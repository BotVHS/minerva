import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent {
  loginForm: FormGroup;
  twoFAForm: FormGroup;

  showPassword = false;
  showTwoFA = false;
  loading = false;
  error = '';

  sessionToken = '';
  userId = '';

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.loginForm = this.fb.group({
      username: ['', [Validators.required]],
      password: ['', [Validators.required]]
    });

    this.twoFAForm = this.fb.group({
      totpCode: ['', [Validators.required, Validators.pattern(/^\d{6}$/)]]
    });
  }

  /**
   * Submit login phase 1
   */
  onLoginSubmit(): void {
    if (this.loginForm.invalid) {
      return;
    }

    this.loading = true;
    this.error = '';

    this.authService.loginPhase1(this.loginForm.value).subscribe({
      next: (response) => {
        // Case 1: User has 2FA enabled - show 2FA form
        if (response.pending2FA && response.sessionToken && response.userId) {
          this.sessionToken = response.sessionToken;
          this.userId = response.userId;
          this.showTwoFA = true;
          this.loading = false;
        }
        // Case 2: User does NOT have 2FA enabled - direct login success
        else if (response.success && response.accessToken) {
          this.loading = false;
          this.router.navigate(['/dashboard']);
        }
        // Case 3: Error
        else if (response.error) {
          this.error = response.error;
          this.loading = false;
        }
      },
      error: (error) => {
        this.error = error.error?.error || 'Error en el login. Comprova les credencials.';
        this.loading = false;
      }
    });
  }

  /**
   * Submit 2FA verification
   */
  on2FASubmit(): void {
    if (this.twoFAForm.invalid) {
      return;
    }

    this.loading = true;
    this.error = '';

    const request = {
      userId: this.userId,
      sessionToken: this.sessionToken,
      totpCode: this.twoFAForm.value.totpCode
    };

    this.authService.verify2FA(request).subscribe({
      next: () => {
        this.loading = false;
        this.router.navigate(['/dashboard']);
      },
      error: (error) => {
        this.error = error.error?.error || 'Codi 2FA incorrecte. Torna-ho a provar.';
        this.loading = false;
        this.twoFAForm.reset();
      }
    });
  }

  /**
   * Toggle password visibility
   */
  togglePasswordVisibility(): void {
    this.showPassword = !this.showPassword;
  }

  /**
   * Cancel 2FA and go back
   */
  cancel2FA(): void {
    this.showTwoFA = false;
    this.sessionToken = '';
    this.userId = '';
    this.twoFAForm.reset();
    this.error = '';
  }
}
