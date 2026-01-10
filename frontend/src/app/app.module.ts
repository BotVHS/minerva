import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { ReactiveFormsModule, FormsModule } from '@angular/forms';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';

// Interceptors
import { AuthInterceptor } from './shared/services/auth.interceptor';

// Auth Components
import { LoginComponent } from './auth/components/login/login.component';

// Dashboard Components
import { DashboardComponent } from './dashboard/dashboard.component';

// Users Components
import { UsersListComponent } from './users/components/users-list/users-list.component';
import { UserFormComponent } from './users/components/user-form/user-form.component';

// Audit Components
import { AuditLogsComponent } from './audit/components/audit-logs/audit-logs.component';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    DashboardComponent,
    UsersListComponent,
    UserFormComponent,
    AuditLogsComponent
  ],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    HttpClientModule,
    ReactiveFormsModule,
    FormsModule,
    AppRoutingModule
  ],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
