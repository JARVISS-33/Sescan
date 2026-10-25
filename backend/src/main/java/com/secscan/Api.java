package com.secscan;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Api {
    public record Login(String password) {}
    public record NewEng(String client, String authRef, String scope, String tester) {}
    public record NewScan(String url, Boolean active, String cookie, Boolean authorized) {}
    public record Patch(String status, String notes, String severity) {}
    public record NewFinding(String title, String severity, String description, String evidence, String fix,
                             String location, String owasp, String cwe, Double cvss) {}

    private static final Set<String> STATUSES = new LinkedHashSet<>(List.of("Open", "Confirmed", "False positive", "Accepted risk"));
    private static final Set<String> SEVS = new LinkedHashSet<>(List.of("Critical", "High", "Medium", "Low", "Info"));
    private static final Map<String, Double> DEFAULT_CVSS = Map.of("Critical", 9.5, "High", 7.5, "Medium", 5.0, "Low", 3.0, "Info", 0.0);
    private static final Pattern HOST = Pattern.compile("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$");

    private final Store store;
    private final Auth auth;
    private final WebScanner scanner;

    public Api(Store store, Auth auth, WebScanner scanner) {
        this.store = store;
        this.auth = auth;
        this.scanner = scanner;
    }

    private static ResponseEntity<Map<String, Object>> err(HttpStatus s, String m) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", m == null ? "Invalid request" : m);
        return ResponseEntity.status(s).body(body);
    }

    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String nz(String s) {
        return s == null ? "" : s.trim();
    }

    /** Turns pasted text like "https://www.Example.com/path" into clean host names, one per line. */
    static List<String> parseScope(String raw) {
        Set<String> out = new LinkedHashSet<>();
        if (raw != null) {
            for (String line : raw.split("[\\r\\n,]+")) {
                String s = line.trim().toLowerCase(Locale.ROOT).replaceFirst("^[a-z]+://", "").replaceFirst("^\\*\\.", "");
                int cut = s.indexOf('/');
                if (cut >= 0) s = s.substring(0, cut);
                cut = s.indexOf(':');
                if (cut >= 0) s = s.substring(0, cut);
                if (HOST.matcher(s).matches()) out.add(s);
            }
        }
        return new ArrayList<>(out);
    }

    // ---------- login ----------
    @PostMapping("/api/login")
    public ResponseEntity<?> login(@RequestBody Login b, HttpServletRequest req) {
        try {
            String t = auth.login(b.password(), req.getRemoteAddr());
            if (t == null) return err(HttpStatus.UNAUTHORIZED, "Wrong password");
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("token", t);
            return ResponseEntity.ok(ok);
        } catch (IllegalStateException e) {
            return err(HttpStatus.TOO_MANY_REQUESTS, e.getMessage());
        }
    }

    // ---------- engagements ----------
    @GetMapping("/api/engagements")
    public List<Map<String, Object>> engagements() {
        return store.engagements();
    }

    @PostMapping("/api/engagements")
    public ResponseEntity<?> newEngagement(@RequestBody NewEng b) {
        if (blank(b.client()) || blank(b.authRef()))
            return err(HttpStatus.BAD_REQUEST, "Client name and authorization reference are required.");
        List<String> scope = parseScope(b.scope());
        if (scope.isEmpty())
            return err(HttpStatus.BAD_REQUEST, "Add at least one in-scope domain, one per line (for example example.com).");
        String id = store.addEngagement(b.client().trim(), b.authRef().trim(), String.join("\n", scope), nz(b.tester()));
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("id", id);
        return ResponseEntity.ok(ok);
    }

    @GetMapping("/api/engagements/{id}")
    public ResponseEntity<?> detail(@PathVariable String id) {
        Map<String, Object> e = store.engagement(id);
        if (e == null) return ResponseEntity.notFound().build();
        List<Map<String, Object>> f = store.findings(id);
        int score = Report.score(f);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("engagement", e);
        out.put("scans", store.scans(id));
        out.put("findings", f);
        out.put("score", score);
        out.put("grade", Report.grade(score));
        return ResponseEntity.ok(out);
    }

    // ---------- scans ----------
    @PostMapping("/api/engagements/{id}/scans/web")
    public ResponseEntity<?> startWebScan(@PathVariable String id, @RequestBody NewScan b) {
        Map<String, Object> e = store.engagement(id);
        if (e == null) return ResponseEntity.notFound().build();
        if (!Boolean.TRUE.equals(b.authorized()))
            return err(HttpStatus.BAD_REQUEST, "Confirm that this target is covered by the engagement's written authorization.");
        if (b.cookie() != null && (b.cookie().contains("\r") || b.cookie().contains("\n")))
            return err(HttpStatus.BAD_REQUEST, "The cookie value is not valid.");
        List<String> scope = Arrays.asList(String.valueOf(e.get("scope")).split("\n"));
        String url = nz(b.url());
        try {
            WebScanner.validateTarget(url, scope);
        } catch (IllegalArgumentException ex) {
            return err(HttpStatus.BAD_REQUEST, ex.getMessage());
        }
        String sid = store.addScan(id, "WEB", url);
        scanner.start(id, sid, url, Boolean.TRUE.equals(b.active()), b.cookie(), scope);
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("id", sid);
        return ResponseEntity.ok(ok);
    }

    @GetMapping("/api/scans/{id}")
    public ResponseEntity<?> scanStatus(@PathVariable String id) {
        Map<String, Object> s = store.scan(id);
        if (s == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(s);
    }

    // ---------- findings ----------
    @PostMapping("/api/engagements/{id}/findings")
    public ResponseEntity<?> addManual(@PathVariable String id, @RequestBody NewFinding b) {
        if (store.engagement(id) == null) return ResponseEntity.notFound().build();
        if (blank(b.title())) return err(HttpStatus.BAD_REQUEST, "A title is required.");
        String sev = SEVS.contains(b.severity()) ? b.severity() : "Medium";
        double cvss = b.cvss() != null ? Math.max(0, Math.min(10, b.cvss())) : DEFAULT_CVSS.get(sev);
        store.addFinding(id, null, "MANUAL", null, b.title().trim(), sev, "High", cvss, nz(b.owasp()), nz(b.cwe()),
                nz(b.location()), 1, nz(b.evidence()), nz(b.description()), nz(b.fix()));
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("ok", true);
        return ResponseEntity.ok(ok);
    }

    @PatchMapping("/api/findings/{id}")
    public ResponseEntity<?> patch(@PathVariable String id, @RequestBody Patch b) {
        if (!STATUSES.contains(b.status()) || !SEVS.contains(b.severity()))
            return err(HttpStatus.BAD_REQUEST, "Invalid status or severity.");
        int n = store.updateFinding(id, b.status(), b.notes() == null ? "" : b.notes(), b.severity());
        if (n == 0) return ResponseEntity.notFound().build();
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("ok", true);
        return ResponseEntity.ok(ok);
    }

    // ---------- report ----------
    @GetMapping(value = "/api/engagements/{id}/report", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> report(@PathVariable String id) {
        Map<String, Object> e = store.engagement(id);
        if (e == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(Report.html(e, store.scans(id), store.findings(id)));
    }
}
