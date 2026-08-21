# Setup Instructions

This document explains how to run the Audit Log Service locally, including the required software, environment variables, database preparation, and startup commands.

## 1. Prerequisites

Before starting the application, make sure the following are available:

- Java 17 or newer
- Maven 3.9 or newer
- MySQL 8.x or a reachable MySQL server
- Git
- A terminal such as PowerShell, bash, or zsh

## 2. Clone the repository

```bash
git clone <repository-url>
cd AuditLogService
```

## 3. Configure environment variables

The project reads runtime configuration from environment variables.

### PowerShell

```powershell
$env:DB_URL = "jdbc:mysql://localhost:3306/audit_log?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
$env:DB_USERNAME = "app_user"
$env:DB_PASSWORD = "your-strong-password"
$env:JWT_SECRET = "replace-with-a-long-random-secret"
$env:JWT_EXPIRATION_MS = "3600000"
```

### Bash / zsh

```bash
export DB_URL="jdbc:mysql://localhost:3306/audit_log?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
export DB_USERNAME="app_user"
export DB_PASSWORD="your-strong-password"
export JWT_SECRET="replace-with-a-long-random-secret"
export JWT_EXPIRATION_MS="3600000"
```

> Important: do not store real secrets in the repository. In production, prefer a secure secret manager or vault.

## 4. Create the database

Create the MySQL database and user, then grant access:

```sql
CREATE DATABASE audit_log;
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'your-strong-password';
GRANT ALL PRIVILEGES ON audit_log.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;
```

The application is configured with `spring.jpa.hibernate.ddl-auto=update`, so it will create the tables automatically on startup.

## 5. Build the project

From the project root, run:

```bash
mvn clean package
```

## 6. Run the application

```bash
mvn spring-boot:run
```

Once started, the service is available at:

```text
http://localhost:8080
```

## 7. Access Swagger and API docs

Open the Swagger UI here:

```text
http://localhost:8080/swagger-ui/index.html
```

OpenAPI JSON is available at:

```text
http://localhost:8080/v3/api-docs
```

## 8. Generate a JWT

The app exposes a public token endpoint:

```http
POST /auth/token
```

Example request body:

```json
{
  "username": "admin-user",
  "password": "your-password"
}
```

Example response:

```json
{
  "token": "<jwt-token>"
}
```

Use the token in the Authorization header for protected endpoints:

```http
Authorization: Bearer <jwt-token>
```

## 9. Test profile setup

The project includes a test profile using H2 so test execution can run without a live MySQL instance.

### PowerShell example

```powershell
$env:TEST_DB_URL = "jdbc:h2:mem:auditdb;MODE=MYSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
$env:TEST_DB_USERNAME = "sa"
$env:TEST_DB_PASSWORD = ""
$env:TEST_JWT_SECRET = "test-secret-key-123456789012345678901234567890"
$env:TEST_JWT_EXPIRATION_MS = "3600000"
```

Run the tests with:

```bash
mvn test
```

## 10. Notes and caveats

- This is a working prototype and not yet a fully hardened production evidence platform.
- Use strong secrets and managed secret storage in real deployments.
- Prefer migration tools for production database schema changes.
- Keep DB credentials and JWT secrets out of source control.
- Review the project documentation in the `docs/` folder for policy, security, and readiness review notes.

## 11. Quick start summary

```bash
mvn clean package
mvn spring-boot:run
```

Then open:

```text
http://localhost:8080/swagger-ui/index.html
```

Use `/auth/token` to obtain a JWT, then call protected `/audit` endpoints with `Authorization: Bearer ...`.
