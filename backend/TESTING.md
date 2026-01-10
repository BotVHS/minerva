# 🧪 Guia de Testing - Minerva Backend

Aquest document descriu com executar i mantenir els tests del backend Minerva.

## 📋 Índex

- [Suite de Tests](#suite-de-tests)
- [Execució de Tests](#execució-de-tests)
- [Code Coverage](#code-coverage)
- [Tests Unitaris](#tests-unitaris)
- [Tests d'Integració](#tests-dintegraci)
- [Tests de Seguretat](#tests-de-seguretat)
- [CI/CD](#cicd)

---

## 📦 Suite de Tests

### Tests Implementats

| Component | Tipus | Fitxer | Tests |
|-----------|-------|--------|-------|
| **PasswordHashService** | Unitari | `PasswordHashServiceTest.java` | 15 tests |
| **TotpService** | Unitari | `TotpServiceTest.java` | 18 tests |
| **TokenService** | Unitari | `TokenServiceTest.java` | 13 tests |
| **AuthResource** | Integració | `AuthResourceIT.java` | 8 tests |
| **UserResource** | Integració | `UserResourceIT.java` | 15 tests |
| **Seguretat OWASP** | Seguretat | `SecurityTest.java` | 15 tests |

**Total: 84+ tests** cobreixen funcionalitats crítiques de seguretat.

---

## 🚀 Execució de Tests

### Prerequisits

```bash
# Java 17+
java -version

# Maven 3.8+
mvn -version

# MongoDB executant-se (per tests d'integració)
docker run -d --name test-mongo -p 27017:27017 mongo:7.0
```

### Executar Tots els Tests

```bash
cd backend

# Executar tots els tests (unitaris + integració)
./mvnw test

# O a Windows
.\mvnw.cmd test
```

### Executar Tests Específics

```bash
# Només tests unitaris
./mvnw test -Dtest="*Test"

# Només tests d'integració
./mvnw test -Dtest="*IT"

# Test concret
./mvnw test -Dtest=PasswordHashServiceTest

# Mètode específic
./mvnw test -Dtest=PasswordHashServiceTest#testHashPassword
```

### Executar Tests de Seguretat

```bash
./mvnw test -Dtest=SecurityTest
```

### Mode Verbose

```bash
# Veure sortida detallada
./mvnw test -X

# Només errors
./mvnw test -q
```

---

## 📊 Code Coverage

### Generar Informe de Coverage

```bash
# Executar tests i generar informe JaCoCo
./mvnw clean test jacoco:report

# L'informe HTML es genera a:
# target/site/jacoco/index.html
```

### Visualitzar Coverage

```bash
# Obrir informe en navegador (Windows)
start target/site/jacoco/index.html

# Linux/Mac
open target/site/jacoco/index.html
```

### Objectius de Coverage

| Mètrica | Objectiu Mínim | Objectiu Ideal |
|---------|----------------|----------------|
| Line Coverage | 70% | 85% |
| Branch Coverage | 60% | 80% |
| Class Coverage | 80% | 95% |

### Verificar Coverage Mínim

```bash
# JaCoCo verificarà automàticament coverage mínim (70%)
./mvnw verify

# Si coverage < 70%, el build fallarà
```

### Coverage per Component

```bash
# Veure coverage per package
./mvnw jacoco:report
# Consulta: target/site/jacoco/index.html

# Components crítics que necessiten alt coverage:
# - cat.minerva.security.*  (>85%)
# - cat.minerva.service.*   (>80%)
# - cat.minerva.resource.*  (>75%)
```

---

## 🔬 Tests Unitaris

### PasswordHashServiceTest

**Què verifica:**
- Hashing Argon2id correcte
- Salts únics per cada password
- Verificació de passwords
- Política de contrasenyes fortes
- Generació de contrasenyes temporals
- Resistència a timing attacks

**Executar:**
```bash
./mvnw test -Dtest=PasswordHashServiceTest
```

**Exemple d'execució:**
```
[INFO] Running cat.minerva.security.PasswordHashServiceTest
[INFO] Tests run: 15, Failures: 0, Errors: 0, Skipped: 0
```

### TotpServiceTest

**Què verifica:**
- Generació de secrets TOTP
- Validació de codis 6 dígits
- Time windows (30 segons)
- Generació de QR codes
- Compatibilitat RFC 6238
- Google Authenticator compatible

**Executar:**
```bash
./mvnw test -Dtest=TotpServiceTest
```

### TokenServiceTest

**Què verifica:**
- Generació de JWT access tokens
- Generació de refresh tokens
- Rotació de tokens
- Revocació de tokens
- Device fingerprinting
- Token hashing (SHA-256)

**Executar:**
```bash
./mvnw test -Dtest=TokenServiceTest
```

---

## 🌐 Tests d'Integració

### AuthResourceIT

**Què verifica:**
- **Flux complet de login 2FA:**
  1. Login fase 1 (credencials)
  2. Login fase 2 (TOTP)
  3. Obtenció de tokens
- **Casos d'error:**
  - Credencials incorrectes
  - Codi 2FA incorrecte
  - Usuari inactiu
  - Compte bloquejat
- **Validacions:**
  - Bean validation
  - Account lockout (5 intents)

**Executar:**
```bash
# Assegura't que MongoDB està executant-se
docker start test-mongo

# Executar tests d'integració
./mvnw test -Dtest=AuthResourceIT
```

**Sortida esperada:**
```
[INFO] Tests run: 8, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 2.5 s
```

### UserResourceIT

**Què verifica:**
- **Creació del primer admin:**
  - Setup inicial del sistema
  - Generació de 2FA (TOTP + QR code)
  - Prevenció de múltiples admins inicials
- **Gestió d'usuaris:**
  - Llistat d'usuaris (només admins)
  - Creació d'usuaris nous amb password temporal
  - Actualització de dades d'usuari
  - Desactivació d'usuaris
- **Control d'accés:**
  - Autenticació requerida per totes les operacions
  - Només ADMIN pot gestionar usuaris
  - Prevenció d'auto-desactivació
- **Validacions:**
  - Format d'email
  - Fortalesa de contrasenyes
  - Unicitat de username
  - Validació de rols
- **Seguretat:**
  - No exposició de password hashes
  - Passwords temporals segurs (16+ caràcters)
  - Password reset obligatori per nous usuaris

**Executar:**
```bash
# Assegura't que MongoDB està executant-se
docker start test-mongo

# Executar tests d'integració
./mvnw test -Dtest=UserResourceIT
```

**Sortida esperada:**
```
[INFO] Tests run: 15, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 3.2 s
```

---

## 🛡️ Tests de Seguretat

### SecurityTest (OWASP Top 10)

**Què verifica:**

#### 1. Injection
- NoSQL injection en login
- NoSQL injection en creació d'usuaris
- JavaScript injection

#### 2. Broken Authentication
- Política de contrasenyes fortes
- Prevenció d'enumeració d'usuaris
- Session timeout

#### 3. Sensitive Data Exposure
- No exposició de password hashes
- Headers de seguretat (HSTS, CSP)

#### 4. XSS (Cross-Site Scripting)
- Sanitització d'input
- Content-Type headers
- X-XSS-Protection

#### 5. Broken Access Control
- Autenticació requerida
- Validació de JWT tokens
- Rebuig de tokens invàlids

#### 6. Security Misconfiguration
- No exposició de versió de servidor
- CSP headers configurats
- X-Frame-Options: DENY

#### 7. CSRF
- Protecció d'operacions POST/PUT/DELETE
- No ús de cookies per tokens

#### Altres
- Rate limiting
- Null byte injection
- Path traversal

**Executar:**
```bash
./mvnw test -Dtest=SecurityTest
```

**Interpretació de resultats:**
```
✅ PASSED - Sistema protegit contra aquest atac
❌ FAILED - Vulnerabilitat detectada (CRÍTICA - Arreglar immediatament!)
```

---

## 🔄 Continuous Integration

### GitHub Actions

Crea `.github/workflows/tests.yml`:

```yaml
name: Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      mongodb:
        image: mongo:7.0
        ports:
          - 27017:27017

    steps:
    - uses: actions/checkout@v3

    - name: Set up JDK 17
      uses: actions/setup-java@v3
      with:
        java-version: '17'
        distribution: 'temurin'

    - name: Cache Maven packages
      uses: actions/cache@v3
      with:
        path: ~/.m2
        key: ${{ runner.os }}-m2-${{ hashFiles('**/pom.xml') }}

    - name: Run tests
      run: cd backend && ./mvnw clean test

    - name: Generate coverage report
      run: cd backend && ./mvnw jacoco:report

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        files: ./backend/target/site/jacoco/jacoco.xml

    - name: Check coverage threshold
      run: cd backend && ./mvnw jacoco:check
```

### Pre-commit Hook

Crea `.git/hooks/pre-commit`:

```bash
#!/bin/bash

echo "🧪 Executant tests abans de commit..."

cd backend
./mvnw test -q

if [ $? -ne 0 ]; then
    echo "❌ Tests fallits! Commit cancel·lat."
    exit 1
fi

echo "✅ Tots els tests passen!"
exit 0
```

Fer-lo executable:
```bash
chmod +x .git/hooks/pre-commit
```

---

## 📝 Escriure Nous Tests

### Estructura d'un Test

```java
@QuarkusTest
@DisplayName("My Service Tests")
class MyServiceTest {

    @Inject
    MyService myService;

    @BeforeEach
    void setUp() {
        // Setup test data
    }

    @Test
    @DisplayName("Should do something correctly")
    void testSomething() {
        // Given - Preparar dades
        String input = "test data";

        // When - Executar acció
        String result = myService.doSomething(input);

        // Then - Verificar resultat
        assertNotNull(result);
        assertEquals("expected", result);
    }

    @AfterEach
    void tearDown() {
        // Cleanup
    }
}
```

### Bones Pràctiques

1. **Noms descriptius**: `testLoginWithValidCredentials()` millor que `test1()`
2. **Given-When-Then**: Estructura clara dels tests
3. **Un assert per test**: Mantenir tests simples
4. **Tests independents**: No dependre de l'ordre d'execució
5. **Clean up**: Netejar dades de test després de cada test
6. **Mocking prudent**: Mockejar dependències externes, no lògica de negoci

---

## 🐛 Debugging Tests

### Executar en Mode Debug

```bash
# Maven debug mode
./mvnw test -Dmaven.surefire.debug

# Connecta el debugger a port 5005
```

### Logs Detallats

```bash
# Veure logs de Quarkus durant tests
./mvnw test -Dquarkus.log.level=DEBUG

# Logs només del nostre package
./mvnw test -Dquarkus.log.category."cat.minerva".level=DEBUG
```

### Test Fallit - Què Fer?

1. **Llegir el missatge d'error**:
   ```
   Expected: <true>
   Actual: <false>
   ```

2. **Revisar el stack trace**: Trobar on falla exactament

3. **Executar el test individualment**:
   ```bash
   ./mvnw test -Dtest=MyTest#failingMethod
   ```

4. **Afegir logs temporals**:
   ```java
   System.out.println("DEBUG: value = " + value);
   ```

5. **Usar debugger**: Posar breakpoints i inspeccionar

---

## 📈 Mètriques de Qualitat

### Executar SonarQube (opcional)

```bash
# Instal·lar SonarQube
docker run -d --name sonarqube -p 9000:9000 sonarqube

# Analitzar projecte
./mvnw sonar:sonar \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=admin \
  -Dsonar.password=admin
```

### Mètriques a Monitoritzar

- **Test Success Rate**: > 99%
- **Code Coverage**: > 70%
- **Test Execution Time**: < 5 minuts
- **Flaky Tests**: 0 (tests que fallen aleatòriament)

---

## 🎯 Checklist abans de Production

- [ ] Tots els tests passen
- [ ] Coverage > 70%
- [ ] Cap test flaky
- [ ] Tests de seguretat passen
- [ ] Tests d'integració passen amb MongoDB real
- [ ] Performance tests executats (si aplicable)
- [ ] Documentation actualitzada

---

## 📞 Suport

Si tens problemes amb els tests:

1. Consulta aquest document
2. Revisa logs de test: `target/surefire-reports/`
3. Executa tests en mode verbose: `./mvnw test -X`
4. Contacta l'equip de desenvolupament

---

**Minerva Security System** - Testing amb cobertura i seguretat garantides 🛡️
