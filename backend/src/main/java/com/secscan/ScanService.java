package com.secscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
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
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

/**
 * The scanner engine. Steps: 1) crawl pages  2) passive checks (only read)
 * 3) probe common sensitive files  4) optional active checks (harmless test inputs)
 * 5) score.
 *
 * Version 2 (Phase A fixes): redirect/www handling, honest coverage report, per-page header
 * checks, sitemap seeding, soft-404 detection, better jQuery/secret detection, scan time limit.
 * Version 3: cookie session per scan, POST form testing, endpoint discovery inside JavaScript files.
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
        CAT.put("actuator", new String[]{"Spring Boot Actuator endpoint exposed", "High", "7.5", "A05", "CWE-200", "passive", "Disable or protect /actuator endpoints (management.endpoints.web.exposure.include, add authentication)."});
        CAT.put("key", new String[]{"Secret or API key visible in page/script", "High", "7.5", "A02", "CWE-798", "passive", "Move secrets to the server, revoke the leaked key and issue a new one."});
        CAT.put("pwhttp", new String[]{"Password form on a page served over HTTP", "High", "7.5", "A02", "CWE-319", "passive", "Serve the whole site over HTTPS and redirect HTTP to HTTPS."});
        CAT.put("csrf", new String[]{"Form without CSRF token", "Medium", "6.5", "A01", "CWE-352", "passive", "Add per-session CSRF tokens and SameSite=Lax/Strict cookies."});
        CAT.put("lib", new String[]{"Outdated jQuery library", "Medium", "6.1", "A06", "CWE-1104", "passive", "Upgrade to a maintained jQuery 3.5+ release and track dependencies."});
        CAT.put("http", new String[]{"Site served over HTTP (no encryption)", "Medium", "5.9", "A02", "CWE-319", "passive", "Enable HTTPS and redirect all HTTP traffic to it."});
        CAT.put("dir", new String[]{"Directory listing enabled", "Medium", "5.3", "A05", "CWE-548", "passive", "Disable directory indexing on the web server."});
        CAT.put("phpinfo", new String[]{"phpinfo() page exposed", "Medium", "5.3", "A05", "CWE-200", "passive", "Delete the phpinfo file from production."});
        CAT.put("status", new String[]{"Apache server-status page exposed", "Medium", "5.3", "A05", "CWE-200", "passive", "Restrict /server-status to localhost or disable mod_status."});
        CAT.put("csp", new String[]{"Missing Content-Security-Policy header", "Medium", "5.3", "A05", "CWE-693", "passive", "Add a CSP that limits script, style and frame sources."});
        CAT.put("cookie", new String[]{"Cookie missing HttpOnly / Secure / SameSite", "Medium", "5.0", "A05", "CWE-1004", "passive", "Set HttpOnly, Secure and SameSite on session cookies."});
        CAT.put("hsts", new String[]{"Missing HSTS header", "Medium", "4.8", "A02", "CWE-319", "passive", "Send Strict-Transport-Security: max-age=31536000; includeSubDomains."});
        CAT.put("redir", new String[]{"Open redirect", "Medium", "4.7", "A01", "CWE-601", "active", "Allow-list redirect targets or use relative paths only."});
        CAT.put("xfo", new String[]{"Clickjacking: no X-Frame-Options / frame-ancestors", "Low", "4.3", "A05", "CWE-1021", "passive", "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."});
        CAT.put("err", new String[]{"Verbose error / stack trace shown", "Low", "3.7", "A05", "CWE-209", "active", "Show generic errors to users and log details on the server."});
        CAT.put("srv", new String[]{"Server technology/version disclosure", "Low", "3.1", "A05", "CWE-200", "passive", "Hide version banners (Server, X-Powered-By) and keep software updated."});
        CAT.put("ds", new String[]{".DS_Store file exposed (leaks file names)", "Low", "3.7", "A05", "CWE-538", "passive", "Delete .DS_Store files from the web root and block dot-files."});
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
    // matches jquery-3.3.1.min.js, jquery.3.3.1.js AND CDN styles like /jquery/3.3.1/jquery.min.js
    private static final Pattern JQUERY = Pattern.compile("jquery[-./@]*(\\d+)\\.(\\d+)\\.(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SKIP_EXT = Pattern.compile(
            ".*\\.(jpg|jpeg|png|gif|svg|ico|webp|css|pdf|zip|gz|woff2?|ttf|mp4|mp3|js|xml)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern REDIR_PARAM = Pattern.compile(
            "(?i)^(url|redirect|redirect_uri|next|return|returnurl|to|dest|destination|continue)$");
    private static final Pattern SITEMAP_LOC = Pattern.compile("<loc>\\s*([^<\\s]+)\\s*</loc>", Pattern.CASE_INSENSITIVE);

    // finds URLs inside JavaScript: fetch("/api/x"), axios.get('/api/x'), $.get(...), xhr.open("GET","/api/x"), url: "/api/x"
    private static final Pattern JS_URL = Pattern.compile(
            "(?:fetch\\(|axios\\.(?:get|post|put|delete|patch)\\(|\\$\\.(?:get|post|getJSON|ajax)\\(|\\.open\\(\\s*['\"][A-Za-z]+['\"]\\s*,|\\burl\\s*:)\\s*[`'\"]([^`'\"\\s]{2,200})[`'\"]");
    private static final String UA = "SecScanStudio/1.0 (educational security scanner)";

    private static final long MAX_SCAN_MILLIS = 6 * 60_000L;   // stop a scan after 6 minutes
    private static final int MAX_POST_FORMS = 8;               // POST forms tested in active mode
    private static final int MAX_JS_ENDPOINTS = 30;            // URLs taken from JavaScript files
    private static final int MAX_TARGETS = 15;                 // pages with parameters tested in active mode
    private static final int MAX_SCRIPTS = 15;                 // same-site scripts read for secrets
    private static final String TIME_MSG = "Time limit reached - the scan was stopped early, so some pages/checks were not covered";

    /** A POST form found while crawling: where it posts, the values a browser would send, and which fields we test. */
    private record PostForm(URI action, Map<String, String> fields, List<String> testable) { }

    private final ScanRepository repo;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ExecutorService pool = Executors.newFixedThreadPool(2);

    /** One HTTP client per scan, with its own cookie jar, so session cookies work and scans never share cookies. */
    private static HttpClient newClient() {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(new java.net.CookieManager())
                .connectTimeout(Duration.ofSeconds(8)).build();
    }

    @Value("${app.max-pages}")
    private int maxPages;

    public ScanService(ScanRepository repo) {
        this.repo = repo;
    }

    /** After a restart (Render free tier sleeps), scans that were RUNNING can never finish: mark them failed. */
    @EventListener(ApplicationReadyEvent.class)
    public void recoverStaleScans() {
        try {
            for (ScanEntity s : repo.findAll()) {
                if ("RUNNING".equals(s.status)) {
                    s.status = "FAILED";
                    s.logText = (s.logText == null ? "" : s.logText) + "FAILED: the server restarted while this scan was running\n";
                    repo.save(s);
                }
            }
        } catch (Exception ignored) { }
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

    private Resp get(HttpClient client, URI start, boolean follow) throws Exception {
        URI cur = start;
        for (int i = 0; i < 5; i++) {
            UrlGuard.check(cur.toString());
            HttpRequest req = HttpRequest.newBuilder(cur).timeout(Duration.ofSeconds(10))
                    .header("User-Agent", UA).GET().build();
            HttpResponse<InputStream> r = client.send(req, HttpResponse.BodyHandlers.ofInputStream());
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

    /** Sends a form as a browser would (application/x-www-form-urlencoded). A redirect after the POST is followed with GET. */
    private Resp post(HttpClient client, URI uri, Map<String, String> fields) throws Exception {
        UrlGuard.check(uri.toString());
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> en : fields.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(URLEncoder.encode(en.getKey(), StandardCharsets.UTF_8)).append('=')
              .append(URLEncoder.encode(en.getValue(), StandardCharsets.UTF_8));
        }
        HttpRequest req = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10))
                .header("User-Agent", UA).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(sb.toString())).build();
        HttpResponse<InputStream> r = client.send(req, HttpResponse.BodyHandlers.ofInputStream());
        int s = r.statusCode();
        Optional<String> loc = r.headers().firstValue("location");
        if (s >= 300 && s < 400 && loc.isPresent()) {
            r.body().close();
            return get(client, uri.resolve(loc.get()), true);
        }
        String body;
        try (InputStream in = r.body()) {
            body = new String(in.readNBytes(1_000_000), StandardCharsets.UTF_8);
        }
        return new Resp(s, r.headers(), body, uri);
    }

    /**
     * The values a browser would send for this form, using simple test values.
     * 'testable' receives the names of fields worth testing (text-like and hidden fields, but not anti-CSRF tokens).
     */
    private static Map<String, String> formFields(Element form, List<String> testable) {
        Map<String, String> out = new LinkedHashMap<>();
        boolean submitDone = false;
        for (Element in : form.select("input[name], textarea[name], select[name]")) {
            String n = in.attr("name");
            if (n.isEmpty() || out.containsKey(n)) continue;
            String type = in.attr("type").toLowerCase();
            String v;
            if (in.tagName().equals("select")) {
                Element o = in.selectFirst("option[value]");
                v = o == null ? "test" : o.attr("value");
            } else if (in.tagName().equals("textarea")) {
                v = "test";
                testable.add(n);
            } else if (type.equals("hidden")) {
                v = in.attr("value");
                if (!n.matches("(?i).*(csrf|token|nonce|authenticity|xsrf).*")) testable.add(n);
            } else if (type.equals("submit")) {
                if (submitDone) continue;
                submitDone = true;
                v = in.attr("value").isEmpty() ? "Submit" : in.attr("value");
            } else if (type.matches("button|reset|image|file|checkbox|radio")) {
                continue;
            } else {
                v = "test";            // text, search, email, password, number ...
                testable.add(n);
            }
            out.put(n, v);
        }
        return out;
    }

    /** URLs mentioned inside JavaScript code (API calls). Template strings and concatenations are skipped. */
    static List<String> jsEndpoints(String js) {
        List<String> out = new ArrayList<>();
        if (js == null || js.isEmpty()) return out;
        Matcher m = JS_URL.matcher(js);
        while (m.find()) {
            String c = m.group(1);
            int after = m.end();
            while (after < js.length() && Character.isWhitespace(js.charAt(after))) after++;
            if (after < js.length() && js.charAt(after) == '+') continue;   // '/a/' + id  is only a prefix of a dynamic URL
            if (c.contains("${") || c.contains("{") || c.contains("+") || c.contains("<") || c.startsWith("#")
                    || c.startsWith("data:") || c.startsWith("javascript:") || c.startsWith("mailto:")) continue;
            if (!out.contains(c)) out.add(c);
        }
        return out;
    }

    /** Adds the API URLs found in a script to the crawl queue (same site only). Returns how many were added. */
    private int queueJsEndpoints(String js, URI pageUri, URI base, Deque<URI> queue, Set<String> seen,
                                 Map<String, Integer> variants, List<URI> targets, boolean active, int already) {
        int added = 0;
        for (String cand : jsEndpoints(js)) {
            if (already + added >= MAX_JS_ENDPOINTS) break;
            try {
                int hash = cand.indexOf('#');
                URI u = pageUri.resolve(hash >= 0 ? cand.substring(0, hash) : cand);
                if (u.getScheme() == null || !(u.getScheme().equals("http") || u.getScheme().equals("https"))) continue;
                if (!sameSite(u, base) || SKIP_EXT.matcher(path(u)).matches()) continue;
                if (u.getRawQuery() != null && active && targets.size() < MAX_TARGETS && targets.stream().noneMatch(t -> path(t).equals(path(u))))
                    targets.add(u);
                if (seen.size() >= maxPages * 3) continue;
                String k = key(u);
                if (seen.contains(k)) continue;
                if (u.getRawQuery() != null && variants.merge(norm(host(u)) + path(u), 1, Integer::sum) > 3) continue;
                seen.add(k);
                queue.add(u);
                added++;
            } catch (Exception ignored) { }
        }
        return added;
    }

    private static Finding f(String id, String page, String evidence) {
        String[] c = CAT.get(id);
        return new Finding(id, c[0], c[1], Double.parseDouble(c[2]), c[3], c[4], c[5], page, evidence, c[6]);
    }

    private static String path(URI u) {
        String p = u.getRawPath();
        return (p == null || p.isEmpty()) ? "/" : p;
    }

    private static String host(URI u) {
        return u.getHost() == null ? "" : u.getHost().toLowerCase();
    }

    /** example.com and www.example.com are the same site. */
    private static String norm(String host) {
        return host.startsWith("www.") ? host.substring(4) : host;
    }

    private static boolean sameSite(URI a, URI b) {
        return norm(host(a)).equals(norm(host(b)));
    }

    /** Key used to remember which URLs we already queued (ignores #fragment, trailing slash, www.). */
    private static String key(URI u) {
        String p = path(u);
        if (p.length() > 1 && p.endsWith("/")) p = p.substring(0, p.length() - 1);
        String q = u.getRawQuery();
        return norm(host(u)) + p + (q == null ? "" : "?" + q);
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

    /** Current (decoded) value of a query parameter, so we do not double-encode it later. */
    private static String queryValue(URI u, String name) {
        String q = u.getRawQuery();
        if (q == null) return "test";
        for (String pair : q.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv[0].equals(name)) return kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
        }
        return "test";
    }

    private static void mask(StringBuilder sb, String s) {
        sb.append(s.length() > 6 ? s.substring(0, 4) + "************" : "********");
    }

    /** First secret-looking text, ignoring normal anti-CSRF tokens. */
    private static String firstSecret(String text) {
        Matcher m = SECRET.matcher(text);
        while (m.find()) {
            String g = m.group();
            // the match may start at "Token", so also look at the few characters before it (csrfToken, xsrf_token ...)
            String around = text.substring(Math.max(0, m.start() - 12), m.end()).toLowerCase();
            if (!around.matches("(?s).*(csrf|xsrf|nonce).*")) return g;
        }
        return null;
    }

    /** True when a probe answer looks like the site's "page not found" page that still says 200. */
    private static boolean looksLikeSoft404(Resp r, Resp soft) {
        if (soft == null) return false;
        int a = r.body().length(), b = soft.body().length();
        return Math.abs(a - b) <= Math.max(50, b / 10);
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
        Consumer<Finding> add = fd -> found.putIfAbsent(fd.id() + "|" + fd.page() + "|" + fd.evidence(), fd);
        List<String> pages = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        final long deadline = System.currentTimeMillis() + MAX_SCAN_MILLIS;
        BooleanSupplier timeUp = () -> System.currentTimeMillis() > deadline;
        HttpClient client = newClient();
        try {
            URI base = URI.create(url);
            String origin = base.getScheme() + "://" + base.getRawAuthority();
            boolean https = "https".equals(base.getScheme());
            say.accept("PHASE 1 Crawl: " + url);

            Deque<URI> queue = new ArrayDeque<>();
            Set<String> seen = new HashSet<>();
            Map<String, Integer> variants = new HashMap<>();   // how many ?query versions of one path we queued
            Set<String> scriptsSeen = new HashSet<>();
            Set<String> cookieSeen = new HashSet<>();
            List<URI> targets = new ArrayList<>();             // URLs with parameters, for active tests
            List<PostForm> postForms = new ArrayList<>();      // POST forms, for active tests
            Set<String> postSeen = new HashSet<>();
            int jsFound = 0;                                   // URLs discovered inside JavaScript
            queue.add(base);
            seen.add(key(base));
            int scriptsFetched = 0, formsFound = 0, paramsTested = 0, blocked = 0;
            int htmlPages = 0, missCsp = 0, missXfo = 0, missXcto = 0, missHsts = 0;
            boolean first = true;

            while (!queue.isEmpty() && pages.size() < maxPages) {
                if (timeUp.getAsBoolean()) {
                    if (!warnings.contains(TIME_MSG)) warnings.add(TIME_MSG);
                    break;
                }
                URI cur = queue.poll();
                Resp r;
                try {
                    r = get(client, cur, true);
                } catch (Exception ex) {
                    say.accept("  could not open " + path(cur) + " (" + ex.getClass().getSimpleName() + ")");
                    if (first) throw new IllegalStateException("The start URL could not be reached");
                    continue;
                }
                int st = r.status();
                String pg = path(r.uri());
                say.accept("  crawled " + pg + " [" + st + "]");
                if (st == 403 || st == 429 || st == 503) blocked++;
                if (st >= 200 && st < 300 && !pages.contains(pg)) pages.add(pg);

                if (first) {
                    first = false;
                    // The start URL may redirect (http -> https, example.com -> www.example.com).
                    // From now on the FINAL address is "the site".
                    URI fin = r.uri();
                    if (!fin.getScheme().equals(base.getScheme()) || !host(fin).equals(host(base))) {
                        say.accept("  start URL redirected to " + fin.getScheme() + "://" + fin.getRawAuthority() + " - using that as the site");
                    }
                    base = fin;
                    origin = base.getScheme() + "://" + base.getRawAuthority();
                    https = "https".equals(base.getScheme());
                    seen.add(key(base));
                    if (st >= 400)
                        warnings.add("The start page answered with HTTP " + st + " - the site may be blocking the scanner or the page does not exist, so results are incomplete");

                    say.accept("PHASE 2 Passive checks: headers, cookies, transport");
                    if (!https) add.accept(f("http", "/ (site-wide)", "The site is served over http://"));
                    String sv = r.h("server"), xp = r.h("x-powered-by");
                    if ((sv != null && sv.matches(".*\\d+\\.\\d+.*")) || xp != null)
                        add.accept(f("srv", "/ (headers)", "Server: " + sv + (xp != null ? "\nX-Powered-By: " + xp : "")));

                    // sitemap.xml gives extra pages the links alone may not reach
                    try {
                        Resp smap = get(client, URI.create(origin + "/sitemap.xml"), true);
                        if (smap.status() == 200) {
                            Matcher lm = SITEMAP_LOC.matcher(smap.body());
                            int added = 0;
                            while (lm.find() && added < maxPages) {
                                try {
                                    URI su = URI.create(lm.group(1).trim().replace("&amp;", "&"));
                                    if (su.getScheme() == null || !(su.getScheme().equals("http") || su.getScheme().equals("https"))) continue;
                                    if (!sameSite(su, base) || SKIP_EXT.matcher(path(su)).matches()) continue;
                                    if (seen.add(key(su))) { queue.add(su); added++; }
                                } catch (Exception ignored) { }
                            }
                            say.accept("  sitemap.xml: " + added + " extra URLs queued");
                        }
                    } catch (Exception ignored) { }
                }

                // cookies: check every response, once per cookie name
                for (String c : r.headers().allValues("set-cookie")) {
                    String cname = c.split("=", 2)[0].trim();
                    if (!cookieSeen.add(cname)) continue;
                    String lc = c.toLowerCase();
                    List<String> miss = new ArrayList<>();
                    if (!lc.contains("httponly")) miss.add("HttpOnly");
                    if (https && !lc.contains("secure")) miss.add("Secure");
                    if (!lc.contains("samesite")) miss.add("SameSite");
                    if (!miss.isEmpty())
                        add.accept(f("cookie", "/ (Set-Cookie)", cname + " is missing: " + String.join(", ", miss)));
                }

                // security headers: check every HTML page, report once at the end
                if (r.isHtml() && st >= 200 && st < 300) {
                    htmlPages++;
                    String csp = r.h("content-security-policy");
                    if (csp == null) missCsp++;
                    if (r.h("x-frame-options") == null && (csp == null || !csp.contains("frame-ancestors"))) missXfo++;
                    if (r.h("x-content-type-options") == null) missXcto++;
                    if (https && r.h("strict-transport-security") == null) missHsts++;
                }

                String body = r.body();
                Matcher stk = STACK.matcher(body);
                if (stk.find()) add.accept(f("err", pg, "Page contains: " + stk.group()));
                if (body.contains("Index of /"))
                    add.accept(f("dir", pg, "Response contains 'Index of /' (directory listing)"));
                String sec = firstSecret(body);
                if (sec != null) {
                    StringBuilder ev = new StringBuilder("Found: ");
                    mask(ev, sec);
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
                Document doc = Jsoup.parse(body, r.uri().toString());

                for (Element s : doc.select("script[src]")) {
                    String src = s.absUrl("src");
                    if (src.isEmpty() || !scriptsSeen.add(src)) continue;   // each script only once
                    Matcher jm = JQUERY.matcher(src);
                    if (jm.find()) {
                        int maj = Integer.parseInt(jm.group(1)), min = Integer.parseInt(jm.group(2));
                        if (maj < 3 || (maj == 3 && min < 5))
                            add.accept(f("lib", pg, "jQuery " + jm.group(1) + "." + jm.group(2) + "." + jm.group(3) + " has known XSS issues (src: " + src + ")"));
                    }
                    try {
                        URI su = URI.create(src);
                        if (sameSite(su, base) && scriptsFetched < MAX_SCRIPTS) {
                            scriptsFetched++;
                            Resp sr = get(client, su, true);
                            String ks = firstSecret(sr.body());
                            if (ks != null) {
                                StringBuilder ev = new StringBuilder("Found: ");
                                mask(ev, ks);
                                add.accept(f("key", path(su), ev.toString()));
                            }
                            jsFound += queueJsEndpoints(sr.body(), su, base, queue, seen, variants, targets, active, jsFound);
                        }
                    } catch (Exception ignored) { }
                }
                for (Element inl : doc.select("script:not([src])"))
                    jsFound += queueJsEndpoints(inl.data(), r.uri(), base, queue, seen, variants, targets, active, jsFound);

                boolean metaToken = false;
                for (Element mt : doc.select("meta[name]"))
                    if (mt.attr("name").toLowerCase().matches(".*(csrf|xsrf).*")) metaToken = true;

                for (Element form : doc.select("form")) {
                    formsFound++;
                    String method = form.attr("method").toLowerCase();
                    String action = form.absUrl("action").isEmpty() ? r.uri().toString() : form.absUrl("action");
                    boolean hasPw = !form.select("input[type=password]").isEmpty();
                    if (hasPw && !https)
                        add.accept(f("pwhttp", pg, "<form action=\"" + form.attr("action") + "\"> has a password field on an http:// page"));
                    if (method.equals("post")) {
                        boolean token = metaToken;
                        for (Element in : form.select("input[type=hidden]"))
                            if (in.attr("name").matches("(?i).*(csrf|token|nonce|authenticity|xsrf).*")) token = true;
                        if (!token)
                            add.accept(f("csrf", pg, "<form method=\"POST\" action=\"" + form.attr("action") + "\"> has no anti-CSRF hidden field or meta token"));
                        if (active && postForms.size() < MAX_POST_FORMS && form.select("input[type=file]").isEmpty()) {
                            try {
                                URI pu = URI.create(action);
                                if (sameSite(pu, base)) {
                                    List<String> testable = new ArrayList<>();
                                    Map<String, String> fields = formFields(form, testable);
                                    List<String> names = new ArrayList<>(fields.keySet());
                                    Collections.sort(names);
                                    if (!testable.isEmpty() && postSeen.add(path(pu) + "|" + String.join(",", names)))
                                        postForms.add(new PostForm(pu, fields, testable.size() > 6 ? new ArrayList<>(testable.subList(0, 6)) : testable));
                                }
                            } catch (Exception ignored) { }
                        }
                    } else if (active) {
                        try {
                            URI au = URI.create(action);
                            // build the GET request the way a browser would: keep hidden fields and defaults
                            for (Map.Entry<String, String> en : formFields(form, new ArrayList<>()).entrySet())
                                au = withParam(au, en.getKey(), en.getValue());
                            // never send test inputs to another website, even if a form points there
                            if (au.getRawQuery() != null && targets.size() < MAX_TARGETS && sameSite(au, base)) targets.add(au);
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
                        if (!sameSite(nu, base)) continue;
                        if (SKIP_EXT.matcher(path(nu)).matches()) continue;
                        if (nu.getRawQuery() != null && active && targets.size() < MAX_TARGETS && targets.stream().noneMatch(t -> path(t).equals(path(nu))))
                            targets.add(nu);
                        if (seen.size() >= maxPages * 3) continue;
                        String k = key(nu);
                        if (seen.contains(k)) continue;
                        // ?page=1, ?page=2 ... must not use up the whole page budget: max 3 per path
                        if (nu.getRawQuery() != null && variants.merge(norm(host(nu)) + path(nu), 1, Integer::sum) > 3) continue;
                        seen.add(k);
                        queue.add(nu);
                    } catch (Exception ignored) { }
                }
            }

            // site-wide header findings, with honest numbers
            if (htmlPages > 0) {
                if (missCsp > 0) add.accept(f("csp", "/ (" + missCsp + " of " + htmlPages + " pages)", "Header 'Content-Security-Policy' missing on " + missCsp + " of " + htmlPages + " HTML pages"));
                if (missXfo > 0) add.accept(f("xfo", "/ (" + missXfo + " of " + htmlPages + " pages)", "Neither X-Frame-Options nor CSP frame-ancestors on " + missXfo + " of " + htmlPages + " HTML pages"));
                if (missXcto > 0) add.accept(f("xcto", "/ (" + missXcto + " of " + htmlPages + " pages)", "Header 'X-Content-Type-Options: nosniff' missing on " + missXcto + " of " + htmlPages + " HTML pages"));
                if (missHsts > 0) add.accept(f("hsts", "/ (" + missHsts + " of " + htmlPages + " pages)", "Header 'Strict-Transport-Security' missing on " + missHsts + " of " + htmlPages + " HTML pages"));
            }
            if (blocked > 0)
                warnings.add(blocked + " response(s) were 403/429/503 - the site may be blocking or rate-limiting the scanner");
            if (pages.isEmpty())
                warnings.add("No pages could be read successfully - this result is NOT a clean bill of health");
            else if (pages.size() == 1 && formsFound == 0)
                warnings.add("Only 1 page and no forms were found. The site may build its pages with JavaScript, which this scanner cannot run yet");
            say.accept("Crawl finished: " + pages.size() + " pages, " + formsFound + " forms, " + targets.size() + " pages with parameters, "
                    + postForms.size() + " POST forms, " + jsFound + " URLs found in JavaScript.");

            say.accept("PHASE 3 Probing common sensitive files");
            Resp soft = null;
            try {
                Resp b = get(client, URI.create(origin + "/secscan-" + Long.toHexString(System.nanoTime()) + ".txt"), true);
                if (b.status() == 200) {
                    soft = b;
                    say.accept("  note: this site answers 200 for pages that do not exist - probe results are compared against that");
                }
            } catch (Exception ignored) { }
            String[][] probes = {{"/.git/config", "git"}, {"/.env", "env"}, {"/backup.zip", "bak"}, {"/backup.sql", "bak"},
                    {"/db.sql", "bak"}, {"/dump.sql", "bak"}, {"/wp-config.php.bak", "bak"}, {"/phpinfo.php", "phpinfo"},
                    {"/server-status", "status"}, {"/actuator/env", "actuator"}, {"/.DS_Store", "ds"},
                    {"/uploads/", "dir"}, {"/backup/", "dir"}, {"/files/", "dir"}};
            for (String[] p : probes) {
                if (timeUp.getAsBoolean()) {
                    if (!warnings.contains(TIME_MSG)) warnings.add(TIME_MSG);
                    break;
                }
                try {
                    Resp r = get(client, URI.create(origin + p[0]), true);
                    boolean hit = false;
                    String ev = "GET " + p[0] + " returned " + r.status();
                    if (r.status() == 200) {
                        switch (p[1]) {
                            case "git" -> hit = r.body().contains("[core]");
                            case "env" -> hit = !r.isHtml() && Pattern.compile("(?m)^[A-Z][A-Z0-9_]*=.+").matcher(r.body()).find();
                            case "bak" -> { hit = !r.isHtml() && !r.body().isEmpty(); ev += " (" + r.h("content-type") + ")"; }
                            case "phpinfo" -> hit = r.body().contains("phpinfo()");
                            case "dir" -> hit = r.body().contains("Index of /");
                            case "status" -> hit = r.body().contains("Apache Server Status");
                            case "actuator" -> hit = r.body().contains("propertySources") || r.body().contains("\"activeProfiles\"");
                            case "ds" -> hit = r.body().contains("Bud1");
                        }
                        if (hit && looksLikeSoft404(r, soft)) hit = false;
                    }
                    say.accept("  " + p[0] + (hit ? "  -> ISSUE" : "  ok"));
                    if (hit) add.accept(f(p[1], p[0], ev));
                    Thread.sleep(150);
                } catch (Exception ex) {
                    say.accept("  " + p[0] + "  (not reachable)");
                }
            }

            if (active) {
                say.accept("PHASE 4 Active checks with harmless test inputs (" + targets.size() + " URL targets, " + postForms.size() + " POST forms)");
                String marker = "ss" + Long.toHexString(System.nanoTime() & 0xffffffL);
                for (URI t : targets) {
                    if (timeUp.getAsBoolean()) {
                        if (!warnings.contains(TIME_MSG)) warnings.add(TIME_MSG);
                        break;
                    }
                    String q = t.getRawQuery() == null ? "" : t.getRawQuery();
                    for (String pair : q.split("&")) {
                        String name = pair.split("=", 2)[0];
                        if (name.isEmpty()) continue;
                        String where = path(t) + "?" + name + "=";
                        try {
                            paramsTested++;
                            Resp x = get(client, withParam(t, name, marker + "<\"'"), true);
                            if (x.isHtml() && x.body().contains(marker + "<\""))
                                add.accept(f("xss", where, "Parameter '" + name + "' came back unescaped: " + marker + "<\"'"));
                            Thread.sleep(150);
                            Resp base0 = get(client, t, true);
                            Resp y = get(client, withParam(t, name, queryValue(t, name) + "'"), true);
                            Matcher m = SQL_ERR.matcher(y.body());
                            if (m.find() && !SQL_ERR.matcher(base0.body()).find())
                                add.accept(f("sqli", where, "Adding a quote caused a database error: " + m.group()));
                            if (STACK.matcher(y.body()).find() && !STACK.matcher(base0.body()).find())
                                add.accept(f("err", where, "A quote in the input caused a stack trace"));
                            Thread.sleep(150);
                            if (REDIR_PARAM.matcher(name).matches()) {
                                Resp z = get(client, withParam(t, name, "https://example.org/"), false);
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
                if (!postForms.isEmpty()) {
                    // note: the log text must not contain the word PHASE followed by a digit (the web page counts those)
                    say.accept("  Testing POST forms - this sends test entries to the forms (a contact form may record them)");
                    for (PostForm pf : postForms) {
                        if (timeUp.getAsBoolean()) {
                            if (!warnings.contains(TIME_MSG)) warnings.add(TIME_MSG);
                            break;
                        }
                        for (String name : pf.testable()) {
                            String where = "POST " + path(pf.action()) + " (field " + name + ")";
                            try {
                                paramsTested++;
                                Map<String, String> a = new LinkedHashMap<>(pf.fields());
                                a.put(name, marker + "<\"'");
                                Resp x = post(client, pf.action(), a);
                                if (x.isHtml() && x.body().contains(marker + "<\""))
                                    add.accept(f("xss", where, "POST field '" + name + "' came back unescaped: " + marker + "<\"'"));
                                Thread.sleep(150);
                                Resp base0 = post(client, pf.action(), pf.fields());
                                Map<String, String> b = new LinkedHashMap<>(pf.fields());
                                b.put(name, pf.fields().get(name) + "'");
                                Resp y = post(client, pf.action(), b);
                                Matcher m = SQL_ERR.matcher(y.body());
                                if (m.find() && !SQL_ERR.matcher(base0.body()).find())
                                    add.accept(f("sqli", where, "Adding a quote to POST field '" + name + "' caused a database error: " + m.group()));
                                if (STACK.matcher(y.body()).find() && !STACK.matcher(base0.body()).find())
                                    add.accept(f("err", where, "A quote in POST field '" + name + "' caused a stack trace"));
                                Thread.sleep(150);
                            } catch (Exception ex) {
                                say.accept("  skipped " + where + " (" + ex.getClass().getSimpleName() + ")");
                            }
                        }
                        say.accept("  tested POST " + path(pf.action()));
                    }
                }
                if (targets.isEmpty() && postForms.isEmpty())
                    warnings.add("Active checks were on, but no page with URL parameters and no form was found, so nothing was tested actively");
            } else {
                say.accept("PHASE 4 Active checks skipped");
            }

            say.accept("PHASE 5 Scoring");
            List<Finding> list = new ArrayList<>(found.values());
            list.sort(Comparator.comparingInt((Finding x) -> ORDER.indexOf(x.severity())).thenComparing(Comparator.comparingDouble(Finding::cvss).reversed()));
            // the same kind of problem counts at most 3 times, so 30 copies of one issue do not zero the score
            Map<String, Integer> perId = new HashMap<>();
            int penalty = 0;
            for (Finding x : list) {
                if (perId.merge(x.id(), 1, Integer::sum) <= 3) penalty += WEIGHT.get(x.severity());
            }
            int score = Math.max(0, 100 - penalty);
            e.score = score;
            e.grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
            e.pagesCount = pages.size();

            Map<String, Object> coverage = new LinkedHashMap<>();
            coverage.put("pagesCrawled", pages.size());
            coverage.put("htmlPages", htmlPages);
            coverage.put("formsFound", formsFound);
            coverage.put("pagesWithParameters", targets.size());
            coverage.put("postFormsTested", postForms.size());
            coverage.put("jsEndpointsFound", jsFound);
            coverage.put("parametersTested", paramsTested);
            coverage.put("activeChecks", active);
            coverage.put("blockedResponses", blocked);
            coverage.put("complete", warnings.isEmpty());
            coverage.put("warnings", warnings);
            e.resultJson = mapper.writeValueAsString(Map.of("pages", pages, "findings", list, "coverage", coverage));
            e.status = "DONE";
            for (String w : warnings) say.accept("WARNING: " + w);
            say.accept("DONE: score " + score + ", grade " + e.grade + ", " + list.size() + " findings"
                    + (warnings.isEmpty() ? "" : " (scan incomplete - see warnings)"));
        } catch (Exception ex) {
            e.status = "FAILED";
            say.accept("FAILED: " + ex.getMessage());
        }
    }
}
