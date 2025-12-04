package cqa.security.jwt.service;

import cqa.security.jwt.model.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
        "application.security.jwt.secret-key=404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970",
        "application.security.jwt.expiration=900000",
        "application.security.jwt.refresh-token.expiration=604800000"
})
public class JwtServiceTest {
    @Autowired
    private JwtService jwtService;

    @Test
    void testTokenGeneration() {
        User user = User.builder()
                .email("test@example.com")
                .password("password")
                .build();

        String token = jwtService.generateToken(user);

        assertNotNull(token);
        assertEquals("test@example.com", jwtService.extractUsername(token));
        assertTrue(jwtService.isTokenValid(token, user));
    }
}
