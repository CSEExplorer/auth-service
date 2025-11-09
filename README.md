# Auth Service

**Auth Service** is a Spring Boot–based microservice responsible for handling authentication and authorization across the platform.  
It provides secure user identity management, JWT-based access and refresh token issuance, multi-factor authentication, and token validation.  
The service also exposes OAuth2-compatible endpoints for other microservices to obtain tokens and integrates with Kafka for asynchronous email notifications.

This service is built to operate as a core security component within a microservices architecture and includes observability endpoints for health, metrics, and monitoring.

---

## 🚀 Quick Highlights

- 🔐 **JWT + Refresh Token Support** – Secure access and refresh token management  
- 👥 **Role-Based Access Control (RBAC)** – Supports roles like `USER`, `ADMIN`  
- 🧂 **Secure Password Hashing & Validation** – Uses bcrypt for password safety  
- 🚫 **Token Revocation / Blacklist Support** – Optional security enhancement  
- 🔁 **OAuth2 / OpenID Connect Support** – Enables token-based integration with other services  
- 📧 **Kafka Integration** – Sends authentication-related emails asynchronously (e.g., OTP, password reset)  
- 🔑 **MFA (Multi-Factor Authentication)** – Adds extra layer of user identity verification  
- 🔄 **Password Recovery Flow** – Secure reset token and email-based recovery  
- 🌐 **JWKS Endpoint** – Provides public keys for token signature verification by other services  
- 🧭 **Health Check & Metrics Endpoints** – For readiness, liveness, and Prometheus scraping  
- 📊 **Observability and Monitoring Ready** – Metrics and logs integrated for system insights

---
## ✨ Features

### 🔐 Authentication & Authorization
- Implements **JWT-based authentication** for stateless security  
- Issues both **Access Tokens** (short-lived) and **Refresh Tokens** (long-lived)  
- Supports **token validation** and **revocation/blacklisting**  
- Uses **Spring Security** for enforcement of role-based access policies  

### 👥 Role-Based Access Control (RBAC)
- Defines clear roles such as `USER`, `ADMIN`, and custom scopes  
- Integrates seamlessly with Spring method-level security annotations (`@PreAuthorize`, `@Secured`)  

### 🧂 Password & Identity Management
- Uses **bcrypt** for password hashing and verification  
- Provides secure **password recovery** flow via email + time-bound reset tokens  
- Supports **multi-factor authentication (MFA)** for critical user actions  

### 🔁 OAuth 2.0 / OpenID Connect Integration
- Acts as an **Authorization Server** for other microservices to obtain access tokens  
- Exposes **JWKS (JSON Web Key Set)** endpoint for verifying token signatures across services 
- **Google OAuth2 Integration** Allows users to log in using their Google accounts, with tokens exchanged for internal JWTs

### 📧 Kafka Integration
- Publishes authentication events (e.g., registration, password reset, MFA OTP) to Kafka  
- Used for **asynchronous email notifications** through downstream Notification Service  

### 🧠 Observability & Monitoring
- Provides **/actuator/health** and **/actuator/metrics** endpoints  
- Integrated with **Prometheus** for metrics scraping  
- Structured logging for easy ingestion into ELK / Grafana Loki stacks  

### 🐳 Deployment Ready
- Containerized with **Docker**  
- Supports **environment-based configuration** for seamless Dev/Stage/Prod setups  
- Easy integration with **API Gateway** or **Service Registry** (Eureka/Consul)

---
## 🏗️ Architecture Overview

The **Auth Service** acts as the central identity provider within the microservices ecosystem.  
It handles all authentication, authorization, and token management logic , MFA(Multi factor Authorizzation) , Magical links and exposes secure APIs for other services to validate and obtain tokens.

### 🔸 Core Components

| Component | Description |
|------------|-------------|
| **Authentication Controller** | Handles login, registration, and token refresh requests |
|**Google OAuth2 Integration** | Allows users to log in using their Google accounts, with tokens exchanged for internal JWTs |
| **Authorization Server Layer** | Issues and validates JWT and refresh tokens for internal/external services |
| **MFA Module** | Generates and validates one-time codes for multi-factor authentication |
| **Password Recovery Module** | Manages secure password reset flows via email links or OTP |
| **JWKS Endpoint** | Publishes JSON Web Key Set (public keys) for cross-service token verification |
| **Kafka Producer** | Sends authentication-related events (e.g., signup, password reset) to Kafka topics |
| **User Repository** | Manages user credentials, roles, and MFA secrets in the database |
| **Observability Layer** | Includes Prometheus metrics, actuator health endpoints, and structured logging |

### 🔹 Interaction Flow

1. **User Authentication**
    - User logs in with credentials → Auth Service validates user → returns JWT + Refresh Token.
    

2. **Service Authorization**
   - Other microservices (e.g., Profile, Course) validate JWTs using the **JWKS endpoint** or introspection endpoint.

3. **Token Refresh**
   - When the access token expires, the client requests a new token using the refresh token.

4. **Event Publishing**
   - Kafka producer sends events like user registration or password recovery to the Notification Service for email/SMS delivery.

5. **Observability**
   - Prometheus scrapes `/actuator/metrics`; logs and health checks are used for monitoring and alerting.

6. **Google OAuth2 Login**
   - User selects “Login with Google” → redirected to Google → upon success, Auth Service exchanges Google token for internal JWT.


---
## ⚙️ Tech Stack

### 🧠 Core Technologies
- **Java 17**
- **Spring Boot 3.2.x**
- **Spring Security 6** – For authentication, authorization, and role management  
- **Spring Authorization Server** – Acts as an OAuth2 provider for token issuance  
- **Nimbus JOSE + JWT** – For signing, parsing, and verifying JWT tokens  
- **Spring Data JPA (Hibernate)** – ORM for database persistence  

### 🗄️ Database & Storage
- **PostgreSQL** – Primary user and token store  
- **Redis (optional)** – For token blacklist, session cache, and rate limiting  

### 📨 Messaging & Notifications
- **Apache Kafka** – For event publishing (registration, MFA, password reset)  
- **Notification Service** – Consumes Kafka events to send email/SMS/OTP  

### 🔑 Identity & OAuth2
- **Google OAuth2** – For federated login with external identity providers  
- **JWKS Endpoint** – Exposes public keys for JWT verification across microservices  

### 🧂 Security
- **BCrypt** – Password hashing and verification  
- **MFA / OTP (TOTP-based)** – Time-based One-Time Password for MFA  
- **CORS & CSRF Protection** – Configured through Spring Security  

### 📈 Observability & Monitoring
- **Spring Boot Actuator** – Health checks and metrics endpoints  
- **Prometheus & Grafana** – Metrics collection and visualization  
- **Structured Logging** – JSON-formatted logs for ELK / Loki stacks  

### 🐳 DevOps & Deployment
- **Docker** – Containerized microservice for portability  
- **Maven** – Build and dependency management  
- **OpenAPI / Swagger** – Auto-generated API documentation  
- **CI/CD Ready** – Compatible with GitHub Actions / Jenkins pipelines  

---

## 🚀 Getting Started

Follow these steps to set up and run the **Auth Service** locally.

---

### 🧩 Prerequisites

Before you begin, make sure you have the following installed:

- [Java 17+](https://adoptium.net/)
- [Maven 3.9+](https://maven.apache.org/)
- [Docker](https://www.docker.com/) (optional but recommended)
- [PostgreSQL](https://www.postgresql.org/)
- [Apache Kafka](https://kafka.apache.org/) (for email event publishing)
- [Prometheus & Grafana](https://prometheus.io/) (for monitoring – optional)

---
---




### ⚙️ 1. Clone the Repository

```bash
git clone https://github.com/CSEExplorer/auth-service.git
cd auth-service
```



### ⚙️ 2. Add `application.properties`

> ⚠️ **Important:**  
> The `application.properties` file is **not committed** to the GitHub repository for security reasons.  
> You must manually create it inside the project’s `src/main/resources/` folder before running the service.

Create the file here:

And add the following **sanitized configuration template**:

```properties
###############################################
# APPLICATION BASICS
###############################################

spring.application.name=Auth-Service

###############################################
# DATASOURCE CONFIGURATION
###############################################
spring.datasource.url=jdbc:postgresql://localhost:5432/userAuth
spring.datasource.username=<your-db-username>
spring.datasource.password=<your-db-password>
spring.datasource.driver-class-name=org.postgresql.Driver

spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect

###############################################
# REDIS CONFIGURATION
###############################################
spring.redis.host=localhost
spring.redis.port=6379
spring.redis.password=
spring.redis.timeout=60000

###############################################
# OAUTH2 CLIENTS (Google / GitHub)
###############################################
oauth2.client.google.client-id=<your-google-client-id>
oauth2.client.google.client-secret=<your-google-client-secret>
oauth2.client.google.redirect-uri=http://localhost:8080/api/auth/oauth/callback/google
oauth2.client.google.scope=profile,email


###############################################
# TOKEN CONFIGURATION
###############################################
security.oauth2.access-token.ttl=3600
security.oauth2.refresh-token.ttl=604800
security.oauth2.reuse-refresh-tokens=false
auth-service.url=http://localhost:8080/
password.reset.ttl-minutes=30

###############################################
# KAFKA CONFIGURATION
###############################################
spring.kafka.bootstrap-servers=localhost:9092
spring.kafka.producer.key-serializer=org.apache.kafka.common.serialization.StringSerializer
spring.kafka.producer.value-serializer=org.springframework.kafka.support.serializer.JsonSerializer
spring.kafka.producer.properties.spring.json.add.type.headers=false

###############################################
# ACTUATOR & METRICS CONFIGURATION
###############################################
management.endpoints.web.exposure.include=health,info,metrics,prometheus,loggers,env,threaddump,httpexchanges
management.endpoint.health.show-details=always
management.endpoints.web.base-path=/actuator

management.metrics.tags.application=${spring.application.name}
management.metrics.export.prometheus.enabled=true
management.metrics.distribution.percentiles-histogram.http.server.requests=true
management.metrics.distribution.percentiles.http.server.requests=0.5,0.9,0.95,0.99

management.health.db.enabled=true
management.health.redis.enabled=true
management.health.kafka.enabled=true
management.health.mail.enabled=true

info.app.name=Auth Service
info.app.version=1.0.0
info.app.description=Handles authentication, token issuance, and validation.

###############################################
# LOGGING CONFIGURATION
###############################################
logging.level.root=INFO
logging.level.com.bookify.auth_service=DEBUG
logging.file.name=logs/auth-service.log
logging.pattern.console=%d{yyyy-MM-dd HH:mm:ss} %-5level [%thread] %logger{36} - %msg%n
logging.pattern.file=%d{yyyy-MM-dd HH:mm:ss} %-5level %logger{36} - %msg%n

```

### ⚙️ 2. `Build the Application`
```
mvn clean install
```
### ⚙️ 2. `Run the Application`

You can run the **Auth Service** in multiple ways — via IntelliJ IDEA, Maven, or Docker.

#### 🧑‍💻 Option 1: Run via IntelliJ IDEA (Recommended for Development)

1. **Open the project**
   - Launch IntelliJ IDEA.
   - Click **File → Open...**
   - Select the project root folder (e.g., `auth-service/`).

2. **Set up SDK**
   - Go to **File → Project Structure → Project**.
   - Ensure **Project SDK** is set to **Java 17** (or higher).
   

3. **Add Maven configuration (if prompted)**
   - IntelliJ will automatically detect the `pom.xml` and import dependencies.
   - If not, right-click `pom.xml` → **Add as Maven Project**.

4. **Create the `application.properties` file**
   - Go to: `src/main/resources/`
   - Create a file named `application.properties` (if it doesn’t exist).
   - Copy the configuration template from the README (see [Step 5 → section 7](#⚙️-7-add-applicationproperties)).

5. **Run PostgreSQL and Kafka**
   - Ensure PostgreSQL is running on `localhost:5432`.
   - Kafka broker should be running on `localhost:9092` (if you’re testing email/MFA).

6. **Build the project**
   - From the top toolbar: Click **Build → Build Project**  
   - Or use the shortcut: `Ctrl + F9`

7. **Run the application**
   - Navigate to: `src/main/java/com/bookify/auth_service/AuthServiceApplication.java`
   - Right-click on the file → **Run 'AuthServiceApplication.main()'**
   - You should see the console output:
     ```
     Tomcat started on port(s): 8080 (http)
     Started AuthServiceApplication in 5.321 seconds
     ```

8. **Verify**
   - Open your browser and go to: 
     - Health Check → http://localhost:8080/actuator/health  
     - Metrics → http://localhost:8080/actuator/prometheus  
   - You should see:
     ```json
     {"status":"UP"}
     ```

---

#### 🧱 Option 2: Run via Maven CLI

```bash
mvn spring-boot:run
```

### 📈 8. Prometheus Setup (Optional but Recommended)

The project includes a **`/prometheus`** folder for monitoring setup.  
This folder contains everything you need to run **Prometheus** locally for metrics collection.

#### 📁 Folder Structure
```
auth-service/
├── prometheus/
│ ├── Dockerfile
│ └── prometheus.yml
```

#### ⚙️ About These Files

- **Dockerfile** → Used to build and run a Prometheus container.  
  You can modify it to change port bindings or volume mounts.  

- **prometheus.yml** → The Prometheus configuration file.  
  It defines scrape targets — for example, your Auth Service metrics endpoint.

Default snippet inside `prometheus.yml`:
```yaml
global:
  scrape_interval: 10s

scrape_configs:
  - job_name: 'auth-service'
    metrics_path: '/actuator/prometheus'
    static_configs:
      - targets: ['host.docker.internal:8080']
```
You can adjust the scrape_interval, add new jobs, or modify the target hostname and port as needed.

📘 Tip: You can later integrate Grafana to visualize these metrics beautifully.
The Auth Service already exposes rich Micrometer metrics (e.g., request count, latency percentiles, DB health).


## 🧾 Complete API Reference — Endpoint-by-Endpoint

This section explains every controller and its endpoints — including purpose, request format, response structure, and behavior.

---
### 1️⃣ **AuthController.java**
Handles **core authentication and token operations** like registration, login, refresh, and validation.

`Base  /api/auth/jwt`

#### 1. `POST /register`
**Purpose:**  
Registers a new user into the system.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "P@ssw0rd!",
  
}
```
**Behavior:**

- Validates that the email isn’t already registered.
- Hashes the password using BCrypt.
- Persists the user record into the database.
- Optionally sends a “welcome” or “verify email” or "user login" to  Kafka event.

**Response (201 Created):**
```json
{
    "email": "saxenaaditya03833@gmail.com",
    "username": "saxenaaditya03833",
    "message": "User registered successfully",
    "userId": "1ed82607-7b38-4bd5-811a-483fdbe22d87"
}
```
#### 1. `POST /login`
**Purpose:**  
Authenticates user credentials and returns access and refresh tokens.

**Request Body:**
```json
{
    "usernameOrEmail": "saxenaaditya381@gmail.com",
    "password":"4AD+6ad+9=0"
}
```
**Behavior:**

- Validates credentials using Spring Security AuthenticationManager.
- Generates JWT access token (15 min expiry) and refresh token (7 days expiry).
- Optionally validates MFA if enabled.

**Response (200 OK):**
```json
{
    "accessToken": "{{access_token}}",
    "refreshToken": "4706b2c8-8476-48be-ab49-010e6c21e8ee"
}
```


#### 1. `POST /refresh`
**Purpose:**  
Issues a new access token using a valid refresh token.

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzUxMiJ9..."
}
```
**Behavior:**

- Validates the refresh token signature and expiry.
- Issues a new access token (and optionally a new refresh token).

**Response (200 OK):**
```json
{
    "accessToken": "{{access_token}}",
    "refreshToken": "4706b2c8-8476-48be-ab49-010e6c21e8ee"
}
```
#### 1. `POST /logout`
**Purpose:**  
Logs out the current authenticated user by invalidating or blacklisting their active JWT access and refresh tokens.


**Request Header:**
```
Authorization: Bearer <access_token>
```
**Behavior:**

- Extracts and verifies the access token from the Authorization header.
- If token revocation or blacklisting is enabled:
- The token is stored in Redis (or another in-memory store) as “blacklisted” until expiry.
- Optionally, also invalidates the refresh token (if provided).
- Future requests using this token will be rejected with HTTP 401 Unauthorized.


**Response (200 OK):**
```json
{
    "message": "Logged out successfully, access token blacklisted and refresh tokens revoked"
}
```
