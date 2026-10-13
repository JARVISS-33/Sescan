package com.secscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class ScanController {
    public record StartRequest(String url, Boolean active, Boolean confirmOwner) {}

    private final ScanRepository repo;
    private final ScanService service;
    private final ObjectMapper mapper = new ObjectMapper();
    // very small rate limit: max 5 scans per hour per visitor
    private final Map<String, List<Instant>> recent = new ConcurrentHashMap<>();

    public ScanController(ScanRepository repo, ScanService service) {
        this.repo = repo;
        this.service = service;
    }

    @GetMapping("/")
    public String health() {
        return "SecScan backend is running";
    }

    @PostMapping("/api/scans")
    public ResponseEntity<Map<String, Object>> start(@RequestBody StartRequest r, HttpServletRequest req) {
        if (r.url() == null || !Boolean.TRUE.equals(r.confirmOwner()))
            return error("You must enter a URL and confirm you have permission to test it.");
        try {
            UrlGuard.check(r.url());
        } catch (IllegalArgumentException ex) {
            return error(ex.getMessage());
        }
        String xff = req.getHeader("X-Forwarded-For");
        String who = xff != null ? xff.split(",")[0].trim() : req.getRemoteAddr();
        List<Instant> list = recent.computeIfAbsent(who, k -> new ArrayList<>());
        synchronized (list) {
            list.removeIf(t -> t.isBefore(Instant.now().minusSeconds(3600)));
            if (list.size() >= 5) return error("Limit reached: 5 scans per hour. Try again later.");
            list.add(Instant.now());
        }
        String id = service.start(r.url().trim(), Boolean.TRUE.equals(r.active()));
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("id", id);
        return ResponseEntity.ok(ok);
    }

    @GetMapping("/api/scans/{id}")
    public ResponseEntity<Map<String, Object>> one(@PathVariable String id) throws Exception {
        Optional<ScanEntity> o = repo.findById(id);
        if (o.isEmpty()) return ResponseEntity.notFound().build();
        ScanEntity e = o.get();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", e.id);
        m.put("url", e.url);
        m.put("status", e.status);
        m.put("score", e.score);
        m.put("grade", e.grade);
        m.put("pagesCount", e.pagesCount);
        m.put("log", e.logText);
        m.put("createdAt", e.createdAt);
        m.put("result", e.resultJson == null ? null : mapper.readTree(e.resultJson));
        return ResponseEntity.ok(m);
    }

    @GetMapping("/api/scans")
    public List<Map<String, Object>> list() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (ScanEntity e : repo.findTop20ByOrderByCreatedAtDesc()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", e.id);
            m.put("url", e.url);
            m.put("status", e.status);
            m.put("score", e.score);
            m.put("grade", e.grade);
            m.put("createdAt", e.createdAt);
            out.add(m);
        }
        return out;
    }

    @GetMapping(value = "/api/scans/{id}/report.html", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> report(@PathVariable String id) throws Exception {
        Optional<ScanEntity> o = repo.findById(id);
        if (o.isEmpty() || o.get().resultJson == null) return ResponseEntity.notFound().build();
        JsonNode result = mapper.readTree(o.get().resultJson);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"security-report.html\"")
                .body(ReportBuilder.html(o.get(), result));
    }

    private static ResponseEntity<Map<String, Object>> error(String msg) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", msg);
        return ResponseEntity.badRequest().body(m);
    }
}
