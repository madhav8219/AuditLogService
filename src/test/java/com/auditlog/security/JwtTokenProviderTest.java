package com.auditlog.security;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class JwtTokenProviderTest {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Value("${test.jwt.secret}")
    private String jwtSecret;

    @Value("${test.jwt.expiration-ms}")
    private long jwtExpirationMs;

    @BeforeEach
    void setUp() {
        assertThat(jwtSecret).isNotBlank();
        assertThat(jwtExpirationMs).isPositive();
        jwtTokenProvider.init();
    }

    @Test
    void shouldGenerateTokenWithSubjectAndRoles() {
        String token = jwtTokenProvider.generateToken("admin-user", List.of("ADMIN", "AUDIT_OFFICER"));

        assertThat(token).isNotBlank();

        Claims claims = jwtTokenProvider.parseClaims(token);
        assertThat(claims.getSubject()).isEqualTo("admin-user");
        assertThat(claims.get("roles")).isInstanceOf(List.class);
        assertThat(((List<?>) claims.get("roles")).stream()
                .map(String::valueOf)
                .toList())
                .containsExactly("ADMIN", "AUDIT_OFFICER");
        assertThat(claims.getExpiration().getTime()).isGreaterThan(System.currentTimeMillis());
    }

    @Test
    void shouldReturnRolesFromToken() {
        String token = jwtTokenProvider.generateToken("security-user", List.of("SECURITY_ANALYST", "COMPLIANCE_REVIEWER"));

        assertThat(jwtTokenProvider.getRoles(token))
                .containsExactlyElementsOf(List.of("SECURITY_ANALYST", "COMPLIANCE_REVIEWER"));
    }

    @Test
    void shouldReturnEmptyRolesForTokenWithoutRolesClaim() {
        String token = jwtTokenProvider.generateToken("service-user", List.of());

        assertThat(jwtTokenProvider.getRoles(token)).isEmpty();
    }
}
