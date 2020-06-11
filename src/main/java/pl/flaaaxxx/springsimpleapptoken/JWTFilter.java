package pl.flaaaxxx.springsimpleapptoken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Set;

import static io.jsonwebtoken.Jwts.parser;

public class JWTFilter extends BasicAuthenticationFilter {

    public JWTFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // pobranie typu autoryzacji
        String header = request.getHeader("Authorization");
        // parsowanie tokena

        UsernamePasswordAuthenticationToken authenticationToken = getAuthenticationByToken(header);
        // SecurityContextHolder przechowuje informacje na temat zalogowanego uzytkownika
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request, response);
    }


    private UsernamePasswordAuthenticationToken getAuthenticationByToken(String header) {
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey("klucz".getBytes())
                .parseClaimsJws(header.replace("Bearer ", ""));

        String username = claimsJws.getBody().get("name").toString();
        String role = claimsJws.getBody().get("role").toString();
        Set<SimpleGrantedAuthority> simpleGrantedAuthorities = Collections.singleton(new SimpleGrantedAuthority(role));

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, simpleGrantedAuthorities);

        return usernamePasswordAuthenticationToken;
    }
}
