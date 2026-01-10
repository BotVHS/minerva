import { Component, OnInit } from '@angular/core';
import { AuthService } from '../auth/services/auth.service';
import { UserService } from '../users/services/user.service';
import { AuditService } from '../audit/services/audit.service';
import { User } from '../shared/models/user.model';
import { AuditLog } from '../shared/models/audit-log.model';

interface DashboardStats {
  totalUsers: number;
  activeUsers: number;
  usersWithTwoFA: number;
  recentLogins: number;
  recentAuditLogs: AuditLog[];
}

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {
  currentUser: User | null = null;
  stats: DashboardStats = {
    totalUsers: 0,
    activeUsers: 0,
    usersWithTwoFA: 0,
    recentLogins: 0,
    recentAuditLogs: []
  };
  loading = true;
  error = '';

  constructor(
    private authService: AuthService,
    private userService: UserService,
    private auditService: AuditService
  ) {}

  ngOnInit(): void {
    this.authService.currentUser$.subscribe(user => {
      this.currentUser = user;
    });

    this.loadDashboardData();
  }

  loadDashboardData(): void {
    this.loading = true;
    this.error = '';

    // Load users stats (only if ADMIN)
    if (this.authService.hasRole('ADMIN')) {
      this.userService.getAllUsers().subscribe({
        next: (users) => {
          this.stats.totalUsers = users.length;
          this.stats.activeUsers = users.filter(u => u.active).length;
          this.stats.usersWithTwoFA = users.filter(u => u.twoFactorEnabled).length;
        },
        error: (err) => {
          console.error('Error loading users:', err);
        }
      });
    }

    // Load recent audit logs
    if (this.authService.hasRole('ADMIN') || this.authService.hasRole('SUPERVISOR')) {
      this.auditService.getAuditLogs().subscribe({
        next: (logs) => {
          this.stats.recentAuditLogs = logs.slice(0, 10);
          this.stats.recentLogins = logs.filter(log =>
            log.action === 'LOGIN_SUCCESS' &&
            this.isRecent(log.timestamp)
          ).length;
          this.loading = false;
        },
        error: (err) => {
          console.error('Error loading audit logs:', err);
          this.error = 'Error carregant dades del dashboard';
          this.loading = false;
        }
      });
    } else {
      this.loading = false;
    }
  }

  private isRecent(timestamp: string): boolean {
    const logDate = new Date(timestamp);
    const oneDayAgo = new Date();
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);
    return logDate > oneDayAgo;
  }

  getActionLabel(action: string): string {
    const labels: { [key: string]: string } = {
      'LOGIN_SUCCESS': 'Login Exitós',
      'LOGIN_FAILURE': 'Login Fallit',
      'LOGOUT': 'Logout',
      'USER_CREATED': 'Usuari Creat',
      'USER_UPDATED': 'Usuari Actualitzat',
      'USER_DELETED': 'Usuari Eliminat',
      'PASSWORD_CHANGED': 'Contrasenya Canviada',
      'TWO_FA_ENABLED': '2FA Activat',
      'TWO_FA_DISABLED': '2FA Desactivat',
      'ACCOUNT_LOCKED': 'Compte Bloquejat',
      'ACCOUNT_UNLOCKED': 'Compte Desbloquejat'
    };
    return labels[action] || action;
  }

  getActionClass(action: string): string {
    if (action.includes('SUCCESS') || action.includes('ENABLED') || action.includes('UNLOCKED') || action === 'USER_CREATED') {
      return 'success';
    } else if (action.includes('FAILURE') || action.includes('DELETED') || action.includes('LOCKED')) {
      return 'danger';
    } else if (action.includes('DISABLED') || action === 'LOGOUT') {
      return 'warning';
    }
    return 'info';
  }

  formatDate(timestamp: string): string {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Ara mateix';
    if (diffMins < 60) return `Fa ${diffMins} min`;

    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `Fa ${diffHours}h`;

    return date.toLocaleDateString('ca-ES', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  hasRole(role: string): boolean {
    return this.authService.hasRole(role);
  }

  getCurrentDateISO(): string {
    return new Date().toISOString();
  }
}
