import { Component, OnInit } from '@angular/core';
import { AuditService } from '../../services/audit.service';
import { AuditLog, AuditAction } from '../../../shared/models/audit-log.model';

@Component({
  selector: 'app-audit-logs',
  templateUrl: './audit-logs.component.html',
  styleUrls: ['./audit-logs.component.scss']
})
export class AuditLogsComponent implements OnInit {
  logs: AuditLog[] = [];
  filteredLogs: AuditLog[] = [];
  loading = true;
  error = '';

  searchTerm = '';
  filterAction: string = 'ALL';
  filterSuccess: string = 'ALL';

  currentPage = 1;
  pageSize = 50;
  totalPages = 1;

  availableActions = Object.values(AuditAction);

  // Expose Math to template
  Math = Math;

  constructor(private auditService: AuditService) {}

  ngOnInit(): void {
    this.loadAuditLogs();
  }

  loadAuditLogs(): void {
    this.loading = true;
    this.error = '';

    this.auditService.getAuditLogs().subscribe({
      next: (logs) => {
        this.logs = logs;
        this.applyFilters();
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Error carregant logs d\'auditoria: ' + (err.error?.error || err.message);
        this.loading = false;
      }
    });
  }

  applyFilters(): void {
    this.filteredLogs = this.logs.filter(log => {
      // Search filter
      const matchesSearch = !this.searchTerm ||
        log.username?.toLowerCase().includes(this.searchTerm.toLowerCase()) ||
        log.ipAddress.toLowerCase().includes(this.searchTerm.toLowerCase()) ||
        log.action.toLowerCase().includes(this.searchTerm.toLowerCase());

      // Action filter
      const matchesAction = this.filterAction === 'ALL' ||
        log.action === this.filterAction;

      // Success filter
      const matchesSuccess = this.filterSuccess === 'ALL' ||
        (this.filterSuccess === 'SUCCESS' && log.success) ||
        (this.filterSuccess === 'FAILURE' && !log.success);

      return matchesSearch && matchesAction && matchesSuccess;
    });

    this.totalPages = Math.ceil(this.filteredLogs.length / this.pageSize);
    this.currentPage = 1;
  }

  onSearchChange(event: Event): void {
    this.searchTerm = (event.target as HTMLInputElement).value;
    this.applyFilters();
  }

  onActionFilterChange(event: Event): void {
    this.filterAction = (event.target as HTMLSelectElement).value;
    this.applyFilters();
  }

  onSuccessFilterChange(event: Event): void {
    this.filterSuccess = (event.target as HTMLSelectElement).value;
    this.applyFilters();
  }

  getPaginatedLogs(): AuditLog[] {
    const startIndex = (this.currentPage - 1) * this.pageSize;
    const endIndex = startIndex + this.pageSize;
    return this.filteredLogs.slice(startIndex, endIndex);
  }

  nextPage(): void {
    if (this.currentPage < this.totalPages) {
      this.currentPage++;
    }
  }

  previousPage(): void {
    if (this.currentPage > 1) {
      this.currentPage--;
    }
  }

  goToPage(page: number): void {
    if (page >= 1 && page <= this.totalPages) {
      this.currentPage = page;
    }
  }

  getPageNumbers(): number[] {
    const pages: number[] = [];
    const maxPagesToShow = 5;
    let startPage = Math.max(1, this.currentPage - Math.floor(maxPagesToShow / 2));
    let endPage = Math.min(this.totalPages, startPage + maxPagesToShow - 1);

    if (endPage - startPage < maxPagesToShow - 1) {
      startPage = Math.max(1, endPage - maxPagesToShow + 1);
    }

    for (let i = startPage; i <= endPage; i++) {
      pages.push(i);
    }

    return pages;
  }

  getActionLabel(action: AuditAction): string {
    const labels: { [key in AuditAction]: string } = {
      [AuditAction.LOGIN_SUCCESS]: 'Login Exitós',
      [AuditAction.LOGIN_FAILURE]: 'Login Fallit',
      [AuditAction.LOGOUT]: 'Logout',
      [AuditAction.USER_CREATED]: 'Usuari Creat',
      [AuditAction.USER_UPDATED]: 'Usuari Actualitzat',
      [AuditAction.USER_DELETED]: 'Usuari Eliminat',
      [AuditAction.PASSWORD_CHANGED]: 'Contrasenya Canviada',
      [AuditAction.TWO_FA_ENABLED]: '2FA Activat',
      [AuditAction.TWO_FA_DISABLED]: '2FA Desactivat',
      [AuditAction.ACCOUNT_LOCKED]: 'Compte Bloquejat',
      [AuditAction.ACCOUNT_UNLOCKED]: 'Compte Desbloquejat'
    };
    return labels[action] || action;
  }

  getActionClass(action: AuditAction): string {
    if (action.toString().includes('SUCCESS') ||
        action === AuditAction.TWO_FA_ENABLED ||
        action === AuditAction.ACCOUNT_UNLOCKED ||
        action === AuditAction.USER_CREATED) {
      return 'success';
    } else if (action.toString().includes('FAILURE') ||
               action === AuditAction.USER_DELETED ||
               action === AuditAction.ACCOUNT_LOCKED) {
      return 'danger';
    } else if (action === AuditAction.TWO_FA_DISABLED || action === AuditAction.LOGOUT) {
      return 'warning';
    }
    return 'info';
  }

  formatDate(timestamp: string): string {
    return new Date(timestamp).toLocaleString('ca-ES', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }

  verifyIntegrity(log: AuditLog): boolean {
    // In a real implementation, this would verify the hash chain
    // For now, we just check if the hash exists
    return !!log.currentHash;
  }

  exportLogs(): void {
    const csvContent = this.generateCSV();
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);

    link.setAttribute('href', url);
    link.setAttribute('download', `audit-logs-${new Date().toISOString()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  private generateCSV(): string {
    const headers = ['Timestamp', 'Action', 'Username', 'IP Address', 'Success', 'Details'];
    const rows = this.filteredLogs.map(log => [
      this.formatDate(log.timestamp),
      this.getActionLabel(log.action),
      log.username || '',
      log.ipAddress,
      log.success ? 'Sí' : 'No',
      log.details || ''
    ]);

    const csvRows = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ];

    return csvRows.join('\n');
  }
}
