package com.secscan;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Protects every /api/ call (except /api/login) with a signed token that lasts 12 hours.
 * The password and signing secret come from Railway variables, never from the code.
 */
@Component
public class Auth implements Filter {
    private static final long TTL_MS = 12L * 3600 * 1000;
    private final String password;
    private final byte[] secret;
    private final Map<String, List<Long>> fails = new ConcurrentHashMap<>();

    public Auth(@Value("${app.password}") String password, @Value("${app.secret}") String secret) {
        if (password.length() < 8) throw new IllegalStateException("APP_PASSWORD must be at least 8 characters");
        if (secret.length() < 24) throw new IllegalStateException("APP_SECRET must be at least 24 characters");
        this.password = password;
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    private String sig(String data) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(secret, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(m.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Returns a token, or null when the password is wrong. Throws when this address is locked out. */
    public String login(String pw, String ip) {
        List<Long> list = fails.computeIfAbsent(ip, k -> new ArrayList<>());
        long now = System.currentTimeMillis();
        synchronized (list) {
            list.removeIf(t -> t < now - 15 * 60 * 1000L);
            if (list.size() >= 8) throw new IllegalStateException("Too many failed attempts. Try again in 15 minutes.");
            boolean ok = pw != null && MessageDigest.isEqual(pw.getBytes(StandardCharsets.UTF_8),
                    password.getBytes(StandardCharsets.UTF_8));
            if (!ok) {
                list.add(now);
                return null;
            }
            list.clear();
        }
        long exp = now + TTL_MS;
        return exp + "." + sig(Long.toString(exp));
    }

    private boolean valid(String token) {
        if (token == null) return false;
        int dot = token.indexOf('.');
        if (dot < 1) return false;
        try {
            long exp = Long.parseLong(token.substring(0, dot));
            if (exp < System.currentTimeMillis()) return false;
            return MessageDigest.isEqual(sig(token.substring(0, dot)).getBytes(StandardCharsets.UTF_8),
                    token.substring(dot + 1).getBytes(StandardCharsets.UTF_8));
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @Override
    public void doFilter(ServletRequest rq, ServletResponse rs, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) rq;
        HttpServletResponse res = (HttpServletResponse) rs;
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("Referrer-Policy", "no-referrer");
        res.setHeader("Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'");
        String path = req.getRequestURI();
        if (path.startsWith("/api/")) {
            res.setHeader("Cache-Control", "no-store");
            if (!path.equals("/api/login")) {
                String h = req.getHeader("Authorization");
                String t = (h != null && h.startsWith("Bearer ")) ? h.substring(7) : null;
                if (!valid(t)) {
                    res.setStatus(401);
                    res.setContentType("application/json");
                    res.getWriter().write("{\"error\":\"Login required\"}");
                    return;
                }
            }
        }
        chain.doFilter(rq, rs);
    }
}
