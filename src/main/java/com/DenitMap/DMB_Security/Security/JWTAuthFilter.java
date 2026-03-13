package com.DenitMap.DMB_Security.Security;

import com.DenitMap.DMB_Security.Service.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JWTAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final CustomUserDetailsService customUserDetailsService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // HttpServlet request means Incoming request, which includes Header& cookies and path and body
        // HTTPServlet response means requests that are sending back to the client from the server
        // Filter chain is the Next filter/controller pipeline, this doFilter(request, response) represents Next filter/controller pipeline


        // taking the Authorization from the request and it looks like this , Bearer eyJhbGciOiJIUzI1Ni...
        String auth = request.getHeader("Authorization");

        // checking if the Auth Starts with the Bearer or not if it doesn't starts with the Bearer then
        // we will Skip JWT validation but we will continue with the request.
        if (auth == null || !auth.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }

//        Removes the Bearer and one space
        String token = auth.substring(7);

        try{

            // Verifying the token Signature and the expiry
            Claims claims = jwtService.validateAndGetClaims(token);

            // if claims.gettype() != access then we will Skip the JWT filter and goes to the next filter
            if (!"access".equals(String.valueOf(claims.get("type")))){
                filterChain.doFilter(request, response);
                return;
            }

            // so get user mail from the claims
            String email = claims.getSubject();

            // checking user already authenticated and already user is authenticated
            if (email !=null && SecurityContextHolder.getContext().getAuthentication() == null){
                // loading the password, roles and authorities
                UserDetails details = customUserDetailsService.loadUserByUsername(email);

                // Creating Authentication object, so this user is authenticated and here are the details
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        details, null, details.getAuthorities()
                );


                // Attaching the Details Like Ip Address and Session INFO
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // this request belongs to this authenticated user, storing the user in the SecurityContextholder
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }catch (Exception exception){
            log.info("JWT authenticaion Failed: {}", exception.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}