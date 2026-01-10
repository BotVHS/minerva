import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuditLog } from '../../shared/models/audit-log.model';

@Injectable({
  providedIn: 'root'
})
export class AuditService {
  private readonly API_URL = '/api/audit';

  constructor(private http: HttpClient) {}

  /**
   * Get all audit logs with optional filters
   */
  getAuditLogs(filters?: {
    userId?: string;
    action?: string;
    startDate?: string;
    endDate?: string;
    limit?: number;
  }): Observable<{ logs: AuditLog[]; total: number }> {
    let params = new HttpParams();

    if (filters?.userId) {
      params = params.set('userId', filters.userId);
    }
    if (filters?.action) {
      params = params.set('action', filters.action);
    }
    if (filters?.startDate) {
      params = params.set('from', filters.startDate);
    }
    if (filters?.endDate) {
      params = params.set('to', filters.endDate);
    }
    if (filters?.limit) {
      params = params.set('limit', filters.limit.toString());
    }

    return this.http.get<{ logs: AuditLog[]; total: number }>(`${this.API_URL}/logs`, { params });
  }

  /**
   * Get audit logs for specific user
   */
  getUserAuditLogs(userId: string): Observable<{ logs: AuditLog[]; total: number }> {
    return this.http.get<{ logs: AuditLog[]; total: number }>(`${this.API_URL}/logs/user/${userId}`);
  }

  /**
   * Verify audit log chain integrity
   */
  verifyIntegrity(): Observable<{ valid: boolean; totalLogs: number; message: string }> {
    return this.http.post<{ valid: boolean; totalLogs: number; message: string }>(`${this.API_URL}/verify-integrity`, {});
  }
}
