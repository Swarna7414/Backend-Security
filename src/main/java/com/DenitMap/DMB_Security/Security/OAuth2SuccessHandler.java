package com.DenitMap.DMB_Security.Security;

import com.DenitMap.DMB_Security.Model.AuthAccount;
import com.DenitMap.DMB_Security.Model.AuthProvider;
import com.DenitMap.DMB_Security.Model.User;
import com.DenitMap.DMB_Security.Repository.AuthAccountRepository;
import com.DenitMap.DMB_Security.Repository.UserRepository;
import com.DenitMap.DMB_Security.Service.AuthService;
import com.DenitMap.DMB_Security.Service.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;

    private final AuthAccountRepository authAccountRepository;

    private final JwtService jwtService;

    private final AuthService authService;

    private static final  String FRONTEND_REDIRECT = "http://localhost:5173/oauth-success";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User principal = (OAuth2User) authentication.getPrincipal();

        String email = principal.getAttribute("email");
        String name = principal.getAttribute("name");
        String sub = principal.getAttribute("sub");

        if (email==null || sub==null){
            response.sendError(400, "Google Login did not return Required Feilds (email/sub)");
            return;
        }

        Optional<AuthAccount> existing = authAccountRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, sub);

        User user;

        if (existing.isPresent()){
            user = existing.get().getUser();
        }else {
            user = userRepository.findByEmail(email).orElseGet(()->{
                String safeName = (name == null || name.isBlank()) ? "User" : name;
                String[] parts = safeName.split(" ",2);

                User created = User.builder().email(email).firstName(parts[0]).lastName(parts.length > 1 ? parts[1] : "")
                        .gender("UNKNOWN").dateOfBirth(LocalDate.of(2000,1,1)).createdAt(Instant.now())
                        .build();

                return userRepository.save(created);


            });

            AuthAccount google = AuthAccount.builder().user(user).provider(AuthProvider.GOOGLE).providerUserId(sub).passwordHash(null).createdAt(Instant.now())
                    .build();

            authAccountRepository.save(google);
        }

        String access = jwtService.generateJWTToken(user);
        String refresh = jwtService.generateRefreshToken(user);

        authService.saveRefresh(user, refresh);

        response.sendRedirect(FRONTEND_REDIRECT + "?access=" + access + "&refresh=" + refresh);
    }
}