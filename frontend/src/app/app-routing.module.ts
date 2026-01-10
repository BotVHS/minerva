import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './auth/components/login/login.component';
import { DashboardComponent } from './dashboard/dashboard.component';
import { UsersListComponent } from './users/components/users-list/users-list.component';
import { UserFormComponent } from './users/components/user-form/user-form.component';
import { AuditLogsComponent } from './audit/components/audit-logs/audit-logs.component';
import { AuthGuard } from './shared/guards/auth.guard';

const routes: Routes = [
  {
    path: 'login',
    component: LoginComponent
  },
  {
    path: 'dashboard',
    component: DashboardComponent,
    canActivate: [AuthGuard]
  },
  {
    path: 'users',
    component: UsersListComponent,
    canActivate: [AuthGuard],
    data: { roles: ['ADMIN'] }
  },
  {
    path: 'users/new',
    component: UserFormComponent,
    canActivate: [AuthGuard],
    data: { roles: ['ADMIN'] }
  },
  {
    path: 'users/edit/:id',
    component: UserFormComponent,
    canActivate: [AuthGuard],
    data: { roles: ['ADMIN'] }
  },
  {
    path: 'audit',
    component: AuditLogsComponent,
    canActivate: [AuthGuard],
    data: { roles: ['ADMIN', 'SUPERVISOR'] }
  },
  {
    path: '',
    redirectTo: '/dashboard',
    pathMatch: 'full'
  },
  {
    path: '**',
    redirectTo: '/dashboard'
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
