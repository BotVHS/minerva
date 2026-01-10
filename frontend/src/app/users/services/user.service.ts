import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  User,
  CreateUserRequest,
  CreateUserResponse,
  UpdateUserRequest
} from '../../shared/models/user.model';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private readonly API_URL = '/api/users';

  constructor(private http: HttpClient) {}

  /**
   * Get all users
   */
  getAllUsers(): Observable<User[]> {
    return this.http.get<User[]>(this.API_URL);
  }

  /**
   * Get user by ID
   */
  getUserById(id: string): Observable<User> {
    return this.http.get<User>(`${this.API_URL}/${id}`);
  }

  /**
   * Create new user
   */
  createUser(request: CreateUserRequest): Observable<CreateUserResponse> {
    return this.http.post<CreateUserResponse>(this.API_URL, request);
  }

  /**
   * Update user
   */
  updateUser(id: string, request: UpdateUserRequest): Observable<User> {
    return this.http.put<User>(`${this.API_URL}/${id}`, request);
  }

  /**
   * Deactivate user
   */
  deactivateUser(id: string): Observable<void> {
    return this.http.delete<void>(`${this.API_URL}/${id}`);
  }
}
