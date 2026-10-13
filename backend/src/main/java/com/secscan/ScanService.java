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
        CAT.put("xfo", new String[]{"Clickjacking: no X-Frame-Options / frame-ancestors", "Low", "4.3", "A05", "CWE-1021", "passive", "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."});
        CAT.put("err", new String[]{"Verbose error / stack trace shown", "Low", "3.7", "A05", "CWE-209", "active", "Show generic errors to users and log details on the server."});
        CAT.put("srv", new String[]{"Server technology/version disclosure", "Low", "3.1", "A05", "CWE-200", "passive", "Hide version banners (Server, X-Powered-By) and keep software updated."});
        CAT.put("mail", new String[]{"Email addresses exposed in page source", "Low", "2.6", "A01", "CWE-200", "passive", "Remove or obfuscate addresses to reduce phishing and spam."});
        CAT.put("xcto", new String[]{"Missing X-Content-Type-Options", "Info", "2.0", "A05", "CWE-693", "passive", "Add X-Content-Type-Options: nosniff."});
    }
    private static final Map<String, Integer> WEIGHT = Map.of("Critical", 25, "High", 12, "Medium", 5, "Low", 2, "Info", 0);
    private static final List<String> ORDER = List.of("Critical", "High", "Medium", "Low", "Info");

    private static final Pattern SQL_ERR = Pattern.compile(
            "(SQL syntax.{0,40}MySQL|SQLSTATE\\[|ORA-\\d{5}|PostgreSQL.{0,30}ERROR|SQLite.{0,20}(error|Exception)|unclosed quotation mark|SQLITE_ERROR|mysqli?_)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern STACK = Pattern.compile(
            "(at [\\w.$]+\\([\\w.]+:\\d+\\)|Traceback \\(most recent call last\\)|Stack trace:|Exception in thread|at Object\\.\\w+ \\()");
    private static final Pattern SECRET = Pattern.compile(
            "(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\\-]{35}|(?i:api[_-]?key|secret|token)\\s*[:=]\\s*['\"][A-Za-z0-9_\\-]{16,}['\"])");
    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    private static final Pattern JQUERY = Pattern.compile("jquery[-.]?(\\d+)\\.(\\d+)\\.(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SKIP_EXT = Pattern.compile(
            ".*\\.(jpg|jpeg|png|gif|svg|ico|webp|css|pdf|zip|gz|woff2?|ttf|mp4|mp3|js|xml)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern REDIR_PARAM = Pattern.compile(
            "(?i)^(url|redirect|redirect_uri|next|return|returnurl|to|dest|destination|continue)$");

    private final ScanRepository repo;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ExecutorService pool = Executors.newFixedThreadPool(2);
    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(8)).build();

    @Value("${app.max-pages}")
    private int maxPages;

    public ScanService(ScanRepository repo) {
        this.repo = repo;
    }

    /** Creates the database row and starts the scan in the background. */
    public String start(String url, boolean active) {
        ScanEntity e = new ScanEntity();
        e.id = UUID.randomUUID().toString();
        e.url = url;
        e.status = "RUNNING";
        e.logText = "";
        e.createdAt = Instant.now();
        repo.save(e);
        pool.submit(() -> run(e.id, url, active));
        return e.id;
    }

    // ---------- helpers ----------
    private record Resp(int status, HttpHeaders headers, String body, URI uri) {
        String h(String name) {
            return headers.firstValue(name).orElse(null);
        }
        boolean isHtml() {
            String ct = h("content-type");
            return ct != null && ct.toLowerCase().contains("html");
        }
    }

    private Resp get(URI start, boolean follow) throws Exception {
        URI cur = start;
        for (int i = 0; i < 5; i++) {
            UrlGuard.check(cur.toString());
            HttpRequest req = HttpRequest.newBuilder(cur).timeout(Duration.ofSeconds(10))
                    .header("User-Agent", "SecScanStudio/1.0 (educational security scanner)").GET().build();
            HttpResponse<InputStream> r = http.send(req, HttpResponse.BodyHandlers.ofInputStream());
            int s = r.statusCode();
            Optional<String> loc = r.headers().firstValue("location");
            if (follow && s >= 300 && s < 400 && loc.isPresent()) {
                r.body().close();
                cur = cur.resolve(loc.get());
                continue;
            }
            String body;
            try (InputStream in = r.body()) {
                body = new String(in.readNBytes(1_000_000), StandardCharsets.UTF_8);
            }
            return new Resp(s, r.headers(), body, cur);
        }
        throw new java.io.IOException("Too many redirects");
    }

    private static Finding f(String id, String page, String evidence) {
        String[] c = CAT.get(id);
        return new Finding(id, c[0], c[1], Double.parseDouble(c[2]), c[3], c[4], c[5], page, evidence, c[6]);
    }

    private static String path(URI u) {
        String p = u.getRawPath();
        return (p == null || p.isEmpty()) ? "/" : p;
    }

    /** Replace one query parameter value (or add it). */
    private static URI withParam(URI u, String name, String value) {
        String q = u.getRawQuery();
        List<String> out = new ArrayList<>();
        boolean done = false;
        if (q != null) {
            for (String pair : q.split("&")) {
                String k = pair.split("=", 2)[0];
                if (k.equals(name)) {
                    out.add(k + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8));
                    done = true;
                } else out.add(pair);
            }
        }
        if (!done) out.add(name + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8));
        String base = u.getScheme() + "://" + u.getRawAuthority() + path(u);
        return URI.create(base + "?" + String.join("&", out));
    }

    private static String queryValue(URI u, String name) {
        String q = u.getRawQuery();
        if (q == null) return "test";
        for (String pair : q.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv[0].equals(name)) return kv.length > 1 ? kv[1] : "";
        }
        return "test";
    }

    private static void mask(StringBuilder sb, String s) {
        sb.append(s.length() > 6 ? s.substring(0, 4) + "************" : "********");
    }

    // ---------- the scan ----------
    private void run(String id, String url, boolean active) {
        ScanEntity e = repo.findById(id).orElseThrow();
        StringBuilder log = new StringBuilder();
        Consumer<String> say = m -> {
            log.append(m).append('\n');
            e.logText = log.toString();
            repo.save(e);
        };
        Map<String, Finding> found = new LinkedHashMap<>();
        Consumer<Finding> add = fd -> found.putIfAbsent(fd.id() + "|" + fd.page(), fd);
        List<String> pages = new ArrayList<>();
        try {
            URI base = URI.create(url);
            String origin = base.getScheme() + "://" + base.getRawAuthority();
            boolean https = "https".equals(base.getScheme());
            say.accept("PHASE 1 Crawl: " + url);

            Deque<URI> queue = new ArrayDeque<>();
            Set<String> seen = new HashSet<>();
            List<URI> targets = new ArrayList<>();      // URLs with parameters, for active tests
            queue.add(base);
            seen.add(base.toString());
            int scriptsFetched = 0;
            boolean first = true;

            while (!queue.isEmpty() && pages.size() < maxPages) {
                URI cur = queue.poll();
                Resp r;
                try {
                    r = get(cur, true);
                } catch (Exception ex) {
                    say.accept("  could not open " + path(cur) + " (" + ex.getClass().getSimpleName() + ")");
                    if (first) throw new IllegalStateException("The start URL could not be reached");
                    continue;
                }
                String pg = path(cur);
                if (!pages.contains(pg)) pages.add(pg);
                say.accept("  crawled " + pg + " [" + r.status() + "]");

                if (first) {
                    first = false;
                    say.accept("PHASE 2 Passive checks: headers, cookies, transport");
                    if (!https) add.accept(f("http", "/ (site-wide)", "Start URL uses http://"));
                    String csp = r.h("content-security-policy");
                    if (csp == null) add.accept(f("csp", "/ (all pages)", "Header 'Content-Security-Policy' not present"));
                    if (r.h("x-frame-options") == null && (csp == null || !csp.contains("frame-ancestors")))
                        add.accept(f("xfo", "/ (all pages)", "Neither X-Frame-Options nor CSP frame-ancestors is set"));
                    if (r.h("x-content-type-options") == null)
                        add.accept(f("xcto", "/ (all pages)", "Header 'X-Content-Type-Options: nosniff' not present"));
                    if (https && r.h("strict-transport-security") == null)
                        add.accept(f("hsts", "/ (all pages)", "Header 'Strict-Transport-Security' not present"));
                    String sv = r.h("server"), xp = r.h("x-powered-by");
                    if ((sv != null && sv.matches(".*\\d+\\.\\d+.*")) || xp != null)
                        add.accept(f("srv", "/ (headers)", "Server: " + sv + (xp != null ? "\nX-Powered-By: " + xp : "")));
                    for (String c : r.headers().allValues("set-cookie")) {
                        String lc = c.toLowerCase();
                        List<String> miss = new ArrayList<>();
                        if (!lc.contains("httponly")) miss.add("HttpOnly");
                        if (https && !lc.contains("secure")) miss.add("Secure");
                        if (!lc.contains("samesite")) miss.add("SameSite");
                        if (!miss.isEmpty())
                            add.accept(f("cookie", "/ (Set-Cookie)", c.split("=", 2)[0] + " is missing: " + String.join(", ", miss)));
                    }
                }

                String body = r.body();
                if (STACK.matcher(body).find()) {
                    Matcher m = STACK.matcher(body);
                    m.find();
                    add.accept(f("err", pg, "Page contains: " + m.group()));
                }
                if (body.contains("Index of /"))
                    add.accept(f("dir", pg, "Response contains 'Index of /' (directory listing)"));
                Matcher sm = SECRET.matcher(body);
                if (sm.find()) {
                    StringBuilder ev = new StringBuilder("Found: ");
                    mask(ev, sm.group());
                    add.accept(f("key", pg, ev.toString()));
                }
                Matcher em = EMAIL.matcher(body);
                int emails = 0;
                String firstMail = null;
                while (em.find()) {
                    emails++;
                    if (firstMail == null) firstMail = em.group();
                }
                if (emails >= 3)
                    add.accept(f("mail", pg, "Found " + emails + " addresses, e.g. " + firstMail.charAt(0) + "***" + firstMail.substring(firstMail.indexOf('@'))));

                if (!r.isHtml()) continue;
                Document doc = Jsoup.parse(body, cur.toString());

                for (Element s : doc.select("script[src]")) {
                    String src = s.absUrl("src");
                    Matcher jm = JQUERY.matcher(src);
                    if (jm.find()) {
                        int maj = Integer.parseInt(jm.group(1)), min = Integer.parseInt(jm.group(2));
                        if (maj < 3 || (maj == 3 && min < 5))
                            add.accept(f("lib", pg, "jQuery " + jm.group(1) + "." + jm.group(2) + "." + jm.group(3) + " has known XSS issues (src: " + src + ")"));
                    }
                    try {
                        URI su = URI.create(src);
                        if (host(su).equals(host(base)) && scriptsFetched < 5) {
                            scriptsFetched++;
                            Resp sr = get(su, true);
                            Matcher km = SECRET.matcher(sr.body());
                            if (km.find()) {
                                StringBuilder ev = new StringBuilder("Found: ");
                                mask(ev, km.group());
                                add.accept(f("key", path(su), ev.toString()));
                            }
                        }
                    } catch (Exception ignored) { }
                }

                for (Element form : doc.select("form")) {
                    String method = form.attr("method").toLowerCase();
                    String action = form.absUrl("action").isEmpty() ? cur.toString() : form.absUrl("action");
                    boolean hasPw = !form.select("input[type=password]").isEmpty();
                    if (hasPw && !https)
                        add.accept(f("pwhttp", pg, "<form action=\"" + form.attr("action") + "\"> has a password field on an http:// page"));
                    if (method.equals("post")) {
                        boolean token = false;
                        for (Element in : form.select("input[type=hidden]"))
                            if (in.attr("name").matches("(?i).*(csrf|token|nonce|authenticity|xsrf).*")) token = true;
                        if (!token)
                            add.accept(f("csrf", pg, "<form method=\"POST\" action=\"" + form.attr("action") + "\"> has no anti-CSRF hidden field"));
                    } else if (active) {
                        try {
                            URI au = URI.create(action);
                            for (Element in : form.select("input[type=text],input[type=search],input:not([type])")) {
                                String n = in.attr("name");
                                if (!n.isEmpty()) au = withParam(au, n, "test");
                            }
                            if (au.getRawQuery() != null && targets.size() < 10) targets.add(au);
                        } catch (Exception ignored) { }
                    }
                }

                for (Element a : doc.select("a[href]")) {
                    String h = a.absUrl("href");
                    int hash = h.indexOf('#');
                    if (hash >= 0) h = h.substring(0, hash);
                    if (h.isEmpty()) continue;
                    try {
                        URI nu = URI.create(h);
                        if (nu.getScheme() == null || !(nu.getScheme().equals("http") || nu.getScheme().equals("https"))) continue;
                        if (!host(nu).equals(host(base))) continue;
                        if (SKIP_EXT.matcher(path(nu)).matches()) continue;
                        if (nu.getRawQuery() != null && active && targets.size() < 10 && targets.stream().noneMatch(t -> path(t).equals(path(nu))))
                            targets.add(nu);
                        if (seen.add(nu.toString()) && seen.size() < maxPages * 3) queue.add(nu);
                    } catch (Exception ignored) { }
                }
            }
            say.accept("Crawl finished: " + pages.size() + " pages, " + targets.size() + " pages with parameters.");

            say.accept("PHASE 3 Probing common sensitive files");
            String[][] probes = {{"/.git/config", "git"}, {"/.env", "env"}, {"/backup.zip", "bak"}, {"/backup.sql", "bak"},
                    {"/db.sql", "bak"}, {"/phpinfo.php", "phpinfo"}, {"/uploads/", "dir"}, {"/backup/", "dir"}, {"/files/", "dir"}};
            for (String[] p : probes) {
                try {
                    Resp r = get(URI.create(origin + p[0]), true);
                    boolean hit = false;
                    String ev = "GET " + p[0] + " returned " + r.status();
                    if (r.status() == 200) {
                        switch (p[1]) {
                            case "git" -> hit = r.body().contains("[core]");
                            case "env" -> hit = !r.isHtml() && Pattern.compile("(?m)^[A-Z][A-Z0-9_]*=.+").matcher(r.body()).find();
                            case "bak" -> { hit = !r.isHtml(); ev += " (" + r.h("content-type") + ")"; }
                            case "phpinfo" -> hit = r.body().contains("phpinfo()");
                            case "dir" -> hit = r.body().contains("Index of /");
                        }
                    }
                    say.accept("  " + p[0] + (hit ? "  -> ISSUE" : "  ok"));
                    if (hit) add.accept(f(p[1], p[0], ev));
                    Thread.sleep(150);
                } catch (Exception ex) {
                    say.accept("  " + p[0] + "  (not reachable)");
                }
            }

            if (active) {
                say.accept("PHASE 4 Active checks with harmless test inputs (" + targets.size() + " targets)");
                String marker = "ss" + Long.toHexString(System.nanoTime() & 0xffffffL);
                for (URI t : targets) {
                    String q = t.getRawQuery() == null ? "" : t.getRawQuery();
                    for (String pair : q.split("&")) {
                        String name = pair.split("=", 2)[0];
                        if (name.isEmpty()) continue;
                        String where = path(t) + "?" + name + "=";
                        try {
                            Resp x = get(withParam(t, name, marker + "<\"'"), true);
                            if (x.body().contains(marker + "<\""))
                                add.accept(f("xss", where, "Parameter '" + name + "' came back unescaped: " + marker + "<\"'"));
                            Thread.sleep(150);
                            Resp base0 = get(t, true);
                            Resp y = get(withParam(t, name, queryValue(t, name) + "'"), true);
                            Matcher m = SQL_ERR.matcher(y.body());
                            if (m.find() && !SQL_ERR.matcher(base0.body()).find())
                                add.accept(f("sqli", where, "Adding a quote caused a database error: " + m.group()));
                            if (STACK.matcher(y.body()).find() && !STACK.matcher(base0.body()).find())
                                add.accept(f("err", where, "A quote in the input caused a stack trace"));
                            Thread.sleep(150);
                            if (REDIR_PARAM.matcher(name).matches()) {
                                Resp z = get(withParam(t, name, "https://example.org/"), false);
                                String loc = z.h("location");
                                if (z.status() >= 300 && z.status() < 400 && loc != null && loc.startsWith("https://example.org"))
                                    add.accept(f("redir", where, "?" + name + "=https://example.org/ -> " + z.status() + " Location: " + loc));
                            }
                        } catch (Exception ex) {
                            say.accept("  skipped " + where + " (" + ex.getClass().getSimpleName() + ")");
                        }
                    }
                    say.accept("  tested " + path(t));
                }
            } else {
                say.accept("PHASE 4 Active checks skipped");
            }

            say.accept("PHASE 5 Scoring");
            List<Finding> list = new ArrayList<>(found.values());
            list.sort(Comparator.comparingInt((Finding x) -> ORDER.indexOf(x.severity())).thenComparing(Comparator.comparingDouble(Finding::cvss).reversed()));
            int penalty = list.stream().mapToInt(x -> WEIGHT.get(x.severity())).sum();
            int score = Math.max(0, 100 - penalty);
            e.score = score;
            e.grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
            e.pagesCount = pages.size();
            e.resultJson = mapper.writeValueAsString(Map.of("pages", pages, "findings", list));
            e.status = "DONE";
            say.accept("DONE: score " + score + ", grade " + e.grade + ", " + list.size() + " findings");
        } catch (Exception ex) {
            e.status = "FAILED";
            say.accept("FAILED: " + ex.getMessage());
        }
    }

    private static String host(URI u) {
        return u.getHost() == null ? "" : u.getHost().toLowerCase();
    }
                            }
