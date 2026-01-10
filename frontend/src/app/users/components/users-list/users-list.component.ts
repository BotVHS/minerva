import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { UserService } from '../../services/user.service';
import { User, UserRole } from '../../../shared/models/user.model';

@Component({
  selector: 'app-users-list',
  templateUrl: './users-list.component.html',
  styleUrls: ['./users-list.component.scss']
})
export class UsersListComponent implements OnInit {
  users: User[] = [];
  filteredUsers: User[] = [];
  loading = true;
  error = '';
  searchTerm = '';
  filterRole: string = 'ALL';
  filterStatus: string = 'ALL';

  constructor(
    private userService: UserService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.loadUsers();
  }

  loadUsers(): void {
    this.loading = true;
    this.error = '';

    this.userService.getAllUsers().subscribe({
      next: (users) => {
        this.users = users;
        this.applyFilters();
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Error carregant usuaris: ' + (err.error?.error || err.message);
        this.loading = false;
      }
    });
  }

  applyFilters(): void {
    this.filteredUsers = this.users.filter(user => {
      // Search filter
      const matchesSearch = !this.searchTerm ||
        user.username.toLowerCase().includes(this.searchTerm.toLowerCase()) ||
        user.email.toLowerCase().includes(this.searchTerm.toLowerCase()) ||
        user.fullName.toLowerCase().includes(this.searchTerm.toLowerCase());

      // Role filter
      const matchesRole = this.filterRole === 'ALL' ||
        user.roles.includes(this.filterRole as UserRole);

      // Status filter
      const matchesStatus = this.filterStatus === 'ALL' ||
        (this.filterStatus === 'ACTIVE' && user.active) ||
        (this.filterStatus === 'INACTIVE' && !user.active);

      return matchesSearch && matchesRole && matchesStatus;
    });
  }

  onSearchChange(event: Event): void {
    this.searchTerm = (event.target as HTMLInputElement).value;
    this.applyFilters();
  }

  onRoleFilterChange(event: Event): void {
    this.filterRole = (event.target as HTMLSelectElement).value;
    this.applyFilters();
  }

  onStatusFilterChange(event: Event): void {
    this.filterStatus = (event.target as HTMLSelectElement).value;
    this.applyFilters();
  }

  createUser(): void {
    this.router.navigate(['/users/new']);
  }

  editUser(user: User): void {
    this.router.navigate(['/users/edit', user.id]);
  }

  deleteUser(user: User): void {
    if (!confirm(`Estàs segur que vols eliminar l'usuari "${user.username}"?`)) {
      return;
    }

    this.userService.deleteUser(user.id).subscribe({
      next: () => {
        this.loadUsers();
      },
      error: (err: any) => {
        alert('Error eliminant usuari: ' + (err.error?.error || err.message));
      }
    });
  }

  toggleUserStatus(user: User): void {
    const updatedUser = { ...user, active: !user.active };
    this.userService.updateUser(user.id, updatedUser).subscribe({
      next: () => {
        this.loadUsers();
      },
      error: (err) => {
        alert('Error actualitzant usuari: ' + (err.error?.error || err.message));
      }
    });
  }

  getRoleBadgeClass(role: UserRole): string {
    const classes: { [key: string]: string } = {
      'ADMIN': 'badge-admin',
      'SUPERVISOR': 'badge-supervisor',
      'ANALISTA': 'badge-analista',
      'CONTRIBUIDOR': 'badge-contribuidor'
    };
    return classes[role] || 'badge-default';
  }

  formatDate(date: string | undefined): string {
    if (!date) return 'Mai';
    return new Date(date).toLocaleDateString('ca-ES', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }
}
