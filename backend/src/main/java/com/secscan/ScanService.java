package com.secscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * The scanner engine. Steps: 1) crawl pages  2) passive checks (only read)
 * 3) probe common sensitive files  4) optional active checks (harmless test inputs)
 * 5) score.
 */
@Service
public class ScanService {

    // ---------- catalog: id -> {title, severity, cvss, owasp, cwe, type, fix} ----------
    private static final Map<String, String[]> CAT = new LinkedHashMap<>();
    static {
        CAT.put("sqli", new String[]{"SQL injection indicator (database error on quote)", "Critical", "9.8", "A03", "CWE-89", "active", "Use parameterized queries / prepared statements; never join user input into SQL."});
        CAT.put("env", new String[]{"Exposed .env file with secrets", "Critical", "9.1", "A05", "CWE-538", "passive", "Remove the file from the web root, block dot-files, and rotate every exposed secret."});
        CAT.put("xss", new String[]{"Reflected XSS (input returned unescaped)", "High", "7.4", "A03", "CWE-79", "active", "Encode output by context, validate input, and add a strict Content-Security-Policy."});
        CAT.put("git", new String[]{"Exposed .git directory", "High", "7.5", "A05", "CWE-538", "passive", "Block access to dot-folders at the web server and remove .git from production."});
        CAT.put("bak", new String[]{"Backup or database dump publicly downloadable", "High", "7.5", "A05", "CWE-530", "passive", "Delete backups from the web root and keep them in private storage."});
        CAT.put("key", new String[]{"Secret or API key visible in page/script", "High", "7.5", "A02", "CWE-798", "passive", "Move secrets to the server, revoke the leaked key and issue a new one."});
        CAT.put("pwhttp", new String[]{"Password form on a page served over HTTP", "High", "7.5", "A02", "CWE-319", "passive", "Serve the whole site over HTTPS and redirect HTTP to HTTPS."});
        CAT.put("csrf", new String[]{"Form without CSRF token", "Medium", "6.5", "A01", "CWE-352", "passive", "Add per-session CSRF tokens and SameSite=Lax/Strict cookies."});
        CAT.put("lib", new String[]{"Outdated jQuery library", "Medium", "6.1", "A06", "CWE-1104", "passive", "Upgrade to a maintained jQuery 3.5+ release and track dependencies."});
        CAT.put("http", new String[]{"Site served over HTTP (no encryption)", "Medium", "5.9", "A02", "CWE-319", "passive", "Enable HTTPS and redirect all HTTP traffic to it."});
        CAT.put("dir", new String[]{"Directory listing enabled", "Medium", "5.3", "A05", "CWE-548", "passive", "Disable directory indexing on the web server."});
        CAT.put("phpinfo", new String[]{"phpinfo() page exposed", "Medium", "5.3", "A05", "CWE-200", "passive", "Delete the phpinfo file from production."});
        CAT.put("csp", new String[]{"Missing Content-Security-Policy header", "Medium", "5.3", "A05", "CWE-693", "passive", "Add a CSP that limits script, style and frame sources."});
        CAT.put("cookie", new String[]{"Cookie missing HttpOnly / Secure / SameSite", "Medium", "5.0", "A05", "CWE-1004", "passive", "Set HttpOnly, Secure and SameSite on session cookies."});
        CAT.put("hsts", new String[]{"Missing HSTS header", "Medium", "4.8", "A02", "CWE-319", "passive", "Send Strict-Transport-Security: max-age=31536000; includeSubDomains."});
        CAT.put("redir", new String[]{"Open redirect", "Medium", "4.7", "A01", "CWE-601", "active", "Allow-list redirect targets or use relative paths only."});
        CAT.put("xfo", new String[]{"Clickjacking: no X-Frame-Options / frame-ancestors", "Low", "4.3", "A05", "CWE-1021", "passive", "Add
