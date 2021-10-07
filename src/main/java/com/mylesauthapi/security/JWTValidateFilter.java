package com.mylesauthapi.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class JWTValidateFilter extends BasicAuthenticationFilter {

    public static final String HEADER_ATRIBUTE = "Authorization";
    public static final String ATRIBUTE_PREFIX = "Bearer ";


    public JWTValidateFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String atribute = request.getHeader(HEADER_ATRIBUTE);

        if (atribute == null) {
            chain.doFilter(request, response);
            return;
        }

        if (!atribute.startsWith(ATRIBUTE_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        String tokenJWT = atribute.replace(ATRIBUTE_PREFIX, "");
        UsernamePasswordAuthenticationToken authenticationToken = getAuthenticationToken(tokenJWT);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthenticationToken(String tokenJWT) {

        String user = JWT.require(Algorithm.HMAC512(JWTAuthFilter.TOKEN_PASSWORD))
                .build()
                .verify(tokenJWT)
                .getSubject();

        if (user == null) {
            return null;
        }


        return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
    }



}
