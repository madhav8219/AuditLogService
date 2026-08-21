# Setup Instructions

This document explains how to run the Audit Log Service locally, including prerequisites, environment variables, database setup, and startup steps.

## 1. Prerequisites

Before running the application, ensure the following are installed:

- Java 17 or newer
- Maven 3.9 or newer
- MySQL 8.x or a reachable MySQL instance
- Git
- A terminal such as PowerShell, bash, or zsh

## 2. Clone the repository

```bash
git clone https://github.com/madhav8219/AuditLogService.git
cd AuditLogService
```

## 3. Configure environment variables

The application expects several configuration values to be provided as environment variables.

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

> Important: do not store production secrets in source-controlled files. Use environment variables or a secret manager in real deployments.

## 4. Prepare the database

Create a MySQL database and grant privileges as shown below:

```sql
CREATE DATABASE audit_log;
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'your-strong-password';
GRANT ALL PRIVILEGES ON audit_log.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;
```

The project uses Spring JPA with `ddl-auto=update`, so the required tables will be created automatically when the application starts.

## 5. Build the project

From the project root, run:

```bash
mvn clean package
```

## 6. Run the application

```bash
mvn spring-boot:run
```

The application will start on:

```text
http://localhost:8080
```

## 7. Open Swagger / API docs

Once the application is running, open:

```text
http://localhost:8080/swagger-ui/index.html
```

OpenAPI JSON is available at:

```text
http://localhost:8080/v3/api-docs
```

## 8. Obtain a JWT token

The service exposes a public token endpoint:

```http
POST /auth/token
```

Example request:

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

Use that token in the request header:

```http
Authorization: Bearer <jwt-token>
```

## 9. Test profile setup

The project includes a test profile that uses H2 instead of MySQL. This is useful for running automated tests without a live database.

### PowerShell example

```powershell
$env:TEST_DB_URL = "jdbc:h2:mem:auditdb;MODE=MYSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
$env:TEST_DB_USERNAME = "sa"
$env:TEST_DB_PASSWORD = ""
$env:TEST_JWT_SECRET = "test-secret-key-123456789012345678901234567890"
$env:TEST_JWT_EXPIRATION_MS = "3600000"
```

Run tests with:

```bash
mvn test
```

## 10. Notes and caveats

- This project is a working prototype and not yet a fully hardened production evidence platform.
- Use managed secret storage and strong random secrets in real deployments.
- Prefer database migration tooling for production schema evolution.
- Keep DB credentials and JWT secrets out of source control.
- Review the supporting documents in the `docs/` folder for security and readiness considerations.

## 11. Quick start summary

```bash
mvn clean package
mvn spring-boot:run
```

Then open:

```text
http://localhost:8080/swagger-ui/index.html
```

Use `/auth/token` to acquire a JWT, then send bearer tokens to the protected `/audit` endpoints.
