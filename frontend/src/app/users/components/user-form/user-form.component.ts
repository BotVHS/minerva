import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { UserService } from '../../services/user.service';
import { User, UserRole, CreateUserRequest, UpdateUserRequest } from '../../../shared/models/user.model';

@Component({
  selector: 'app-user-form',
  templateUrl: './user-form.component.html',
  styleUrls: ['./user-form.component.scss']
})
export class UserFormComponent implements OnInit {
  userForm: FormGroup;
  isEditMode = false;
  userId: string | null = null;
  loading = false;
  error = '';
  availableRoles = Object.values(UserRole);

  constructor(
    private fb: FormBuilder,
    private userService: UserService,
    private route: ActivatedRoute,
    private router: Router
  ) {
    this.userForm = this.fb.group({
      username: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(50)]],
      email: ['', [Validators.required, Validators.email]],
      fullName: ['', [Validators.required, Validators.minLength(3)]],
      password: ['', [Validators.minLength(8)]],
      roles: [[], [Validators.required]],
      active: [true],
      twoFactorEnabled: [false]
    });
  }

  ngOnInit(): void {
    this.userId = this.route.snapshot.paramMap.get('id');
    this.isEditMode = !!this.userId;

    if (this.isEditMode) {
      // Password not required for edit
      this.userForm.get('password')?.clearValidators();
      this.userForm.get('password')?.updateValueAndValidity();
      this.loadUser();
    } else {
      // Password required for create
      this.userForm.get('password')?.setValidators([Validators.required, Validators.minLength(8)]);
      this.userForm.get('password')?.updateValueAndValidity();
    }
  }

  loadUser(): void {
    if (!this.userId) return;

    this.loading = true;
    this.userService.getUserById(this.userId).subscribe({
      next: (user) => {
        this.userForm.patchValue({
          username: user.username,
          email: user.email,
          fullName: user.fullName,
          roles: user.roles,
          active: user.active,
          twoFactorEnabled: user.twoFactorEnabled
        });
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Error carregant usuari: ' + (err.error?.error || err.message);
        this.loading = false;
      }
    });
  }

  onSubmit(): void {
    if (this.userForm.invalid) {
      this.markFormGroupTouched(this.userForm);
      return;
    }

    this.loading = true;
    this.error = '';

    if (this.isEditMode && this.userId) {
      // Update existing user
      const updateRequest: UpdateUserRequest = {
        email: this.userForm.value.email,
        fullName: this.userForm.value.fullName,
        roles: this.userForm.value.roles,
        active: this.userForm.value.active
      };

      // Add password if provided
      if (this.userForm.value.password) {
        updateRequest.password = this.userForm.value.password;
      }

      this.userService.updateUser(this.userId, updateRequest).subscribe({
        next: () => {
          this.router.navigate(['/users']);
        },
        error: (err) => {
          this.error = 'Error actualitzant usuari: ' + (err.error?.error || err.message);
          this.loading = false;
        }
      });
    } else {
      // Create new user
      const createRequest: CreateUserRequest = {
        username: this.userForm.value.username,
        email: this.userForm.value.email,
        fullName: this.userForm.value.fullName,
        password: this.userForm.value.password,
        roles: this.userForm.value.roles
      };

      this.userService.createUser(createRequest).subscribe({
        next: () => {
          this.router.navigate(['/users']);
        },
        error: (err) => {
          this.error = 'Error creant usuari: ' + (err.error?.error || err.message);
          this.loading = false;
        }
      });
    }
  }

  onCancel(): void {
    this.router.navigate(['/users']);
  }

  toggleRole(role: UserRole): void {
    const roles = this.userForm.get('roles')?.value as UserRole[];
    const index = roles.indexOf(role);

    if (index === -1) {
      roles.push(role);
    } else {
      roles.splice(index, 1);
    }

    this.userForm.patchValue({ roles });
  }

  isRoleSelected(role: UserRole): boolean {
    const roles = this.userForm.get('roles')?.value as UserRole[];
    return roles.includes(role);
  }

  private markFormGroupTouched(formGroup: FormGroup): void {
    Object.keys(formGroup.controls).forEach(key => {
      const control = formGroup.get(key);
      control?.markAsTouched();
    });
  }

  isFieldInvalid(fieldName: string): boolean {
    const field = this.userForm.get(fieldName);
    return !!(field && field.invalid && field.touched);
  }

  getFieldError(fieldName: string): string {
    const field = this.userForm.get(fieldName);
    if (!field || !field.errors || !field.touched) return '';

    if (field.errors['required']) return 'Aquest camp és obligatori';
    if (field.errors['email']) return 'Email invàlid';
    if (field.errors['minlength']) {
      const minLength = field.errors['minlength'].requiredLength;
      return `Mínim ${minLength} caràcters`;
    }
    if (field.errors['maxlength']) {
      const maxLength = field.errors['maxlength'].requiredLength;
      return `Màxim ${maxLength} caràcters`;
    }

    return '';
  }
}
