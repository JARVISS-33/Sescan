package com.secscan;

import jakarta.annotation.PostConstruct;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** All database work. Tables are prefixed sc_ so they never clash with the old Sescan tables. */
@Repository
public class Store {
    private final JdbcTemplate db;

    public Store(JdbcTemplate db) {
        this.db = db;
    }

    @PostConstruct
    void createTables() {
        db.execute("CREATE TABLE IF NOT EXISTS sc_engagements (id TEXT PRIMARY KEY, client TEXT NOT NULL, "
                + "auth_ref TEXT NOT NULL, scope TEXT NOT NULL, tester TEXT NOT NULL DEFAULT '', "
                + "created_at TIMESTAMPTZ NOT NULL DEFAULT now())");
        db.execute("CREATE TABLE IF NOT EXISTS sc_scans (id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, "
                + "kind TEXT NOT NULL, target TEXT, status TEXT NOT NULL, log TEXT NOT NULL DEFAULT '', "
                + "pages INT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT now())");
        db.execute("CREATE TABLE IF NOT EXISTS sc_findings (id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, "
                + "scan_id TEXT, source TEXT NOT NULL, rule_id TEXT, title TEXT NOT NULL, severity TEXT NOT NULL, "
                + "confidence TEXT NOT NULL DEFAULT 'Medium', cvss NUMERIC(3,1) NOT NULL DEFAULT 0, owasp TEXT, "
                + "cwe TEXT, location TEXT, occurrences INT NOT NULL DEFAULT 1, evidence TEXT, description TEXT, "
                + "fix TEXT, status TEXT NOT NULL DEFAULT 'Open', notes TEXT NOT NULL DEFAULT '', "
                + "created_at TIMESTAMPTZ NOT NULL DEFAULT now())");
        db.execute("CREATE INDEX IF NOT EXISTS sc_findings_eng ON sc_findings(engagement_id)");
        db.execute("CREATE INDEX IF NOT EXISTS sc_scans_eng ON sc_scans(engagement_id)");
    }

    private static String id() {
        return UUID.randomUUID().toString();
    }

    // ---------- engagements ----------
    public String addEngagement(String client, String authRef, String scope, String tester) {
        String id = id();
        db.update("INSERT INTO sc_engagements(id,client,auth_ref,scope,tester) VALUES(?,?,?,?,?)",
                id, client, authRef, scope, tester);
        return id;
    }

    public List<Map<String, Object>> engagements() {
        return db.queryForList("SELECT e.*, "
                + "(SELECT count(*) FROM sc_findings f WHERE f.engagement_id=e.id AND f.status IN ('Open','Confirmed')) AS open_findings, "
                + "(SELECT count(*) FROM sc_scans s WHERE s.engagement_id=e.id) AS scan_count "
                + "FROM sc_engagements e ORDER BY e.created_at DESC LIMIT 100");
    }

    public Map<String, Object> engagement(String id) {
        List<Map<String, Object>> l = db.queryForList("SELECT * FROM sc_engagements WHERE id=?", id);
        return l.isEmpty() ? null : l.get(0);
    }

    // ---------- scans ----------
    public String addScan(String engagementId, String kind, String target) {
        String id = id();
        db.update("INSERT INTO sc_scans(id,engagement_id,kind,target,status) VALUES(?,?,?,?,'RUNNING')",
                id, engagementId, kind, target);
        return id;
    }

    public Map<String, Object> scan(String id) {
        List<Map<String, Object>> l = db.queryForList(
                "SELECT id,engagement_id,kind,target,status,log,pages,created_at FROM sc_scans WHERE id=?", id);
        return l.isEmpty() ? null : l.get(0);
    }

    public List<Map<String, Object>> scans(String engagementId) {
        return db.queryForList("SELECT id,kind,target,status,pages,created_at FROM sc_scans "
                + "WHERE engagement_id=? ORDER BY created_at DESC LIMIT 20", engagementId);
    }

    public void setLog(String id, String log) {
        db.update("UPDATE sc_scans SET log=? WHERE id=?", log, id);
    }

    public void finishScan(String id, String status, int pages, String log) {
        db.update("UPDATE sc_scans SET status=?, pages=?, log=? WHERE id=?", status, pages, log, id);
    }

    /** A restart kills running scans, so mark them failed instead of leaving them RUNNING forever. */
    public void failRunning() {
        db.update("UPDATE sc_scans SET status='FAILED', log=log || 'Server restarted before this scan finished.' "
                + "WHERE status='RUNNING'");
    }

    // ---------- findings ----------
    public void addFinding(String engagementId, String scanId, String source, String ruleId, String title,
                           String severity, String confidence, double cvss, String owasp, String cwe,
                           String location, int occurrences, String evidence, String description, String fix) {
        db.update("INSERT INTO sc_findings(id,engagement_id,scan_id,source,rule_id,title,severity,confidence,cvss,"
                        + "owasp,cwe,location,occurrences,evidence,description,fix) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                id(), engagementId, scanId, source, ruleId, title, severity, confidence, cvss, owasp, cwe,
                location, occurrences, evidence, description, fix);
    }

    public List<Map<String, Object>> findings(String engagementId) {
        return db.queryForList("SELECT * FROM sc_findings WHERE engagement_id=? ORDER BY CASE severity "
                + "WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, "
                + "cvss DESC, created_at", engagementId);
    }

    public int updateFinding(String id, String status, String notes, String severity) {
        return db.update("UPDATE sc_findings SET status=?, notes=?, severity=? WHERE id=?",
                status, notes, severity, id);
    }
}
