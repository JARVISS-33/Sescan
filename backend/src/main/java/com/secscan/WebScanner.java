package com.secscan;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Website scanner. Differences from the first version: every request is limited to the engagement scope,
 * findings are grouped per rule (pages are listed inside one finding), results carry a confidence level,
 * file probes must match real file content (so single-page apps do not create false alarms), and
 * TLS, CORS, mixed content, sitemap and Spring Actuator checks were added.
 */
@Component
public class WebScanner {

    // ---------------------------------------------------------------- rule catalog
    record Rule(String title, String sev, double cvss, String owasp, String cwe, String why, String fix) {}

    static final String A01 = "A01:2021 Broken Access Control";
    static final String A02 = "A02:2021 Cryptographic Failures";
    static final String A03 = "A03:2021 Injection";
    static final String A05 = "A05:2021 Security Misconfiguration";
    static final String A06 = "A06:2021 Vulnerable and Outdated Components";

    static final Map<String, Rule> R = new LinkedHashMap<>();

    private static void rule(String id, String title, String sev, double cvss, String owasp, String cwe, String why, String fix) {
        R.put(id, new Rule(title, sev, cvss, owasp, cwe, why, fix));
    }

    static {
        rule("sqli", "SQL injection indicator (database error on quote)", "Critical", 9.8, A03, "CWE-89",
                "Attackers may read or change the database, including customer data.",
                "Use parameterized queries / prepared statements; never join user input into SQL.");
        rule("env", "Exposed .env file with secrets", "Critical", 9.1, A05, "CWE-538",
                "Passwords and API keys are downloadable by anyone.",
                "Remove the file from the web root, block dot-files, and rotate every exposed secret.");
        rule("actuator", "Spring Boot Actuator /env endpoint exposed", "High", 8.2, A05, "CWE-215",
                "Configuration values and sometimes secrets are readable without login.",
                "Disable or secure Actuator endpoints and expose only /health.");
        rule("git", "Exposed .git directory", "High", 7.5, A05, "CWE-538",
                "Source code and history can be downloaded, often including secrets.",
                "Block access to dot-folders at the web server and remove .git from production.");
        rule("bak", "Backup or database dump publicly downloadable", "High", 7.5, A05, "CWE-530",
                "Full copies of the site or database can be downloaded.",
                "Delete backups from the web root and keep them in private storage.");
        rule("xss", "Reflected cross-site scripting (input returned unescaped)", "High", 7.4, A03, "CWE-79",
                "Attackers can run script in a victim's browser and steal sessions.",
                "Encode output by context, validate input, and add a strict Content-Security-Policy.");
        rule("key", "Secret or API key visible in page or script", "High", 7.5, A02, "CWE-798",
                "Anyone can copy the key and use the connected service.",
                "Move secrets to the server, revoke the leaked key and issue a new one.");
        rule("pwhttp", "Password form not protected by HTTPS", "High", 7.5, A02, "CWE-319",
                "Passwords can be intercepted on the network.",
                "Serve the whole site over HTTPS and redirect HTTP to HTTPS.");
        rule("tls", "TLS certificate problem (invalid, untrusted or wrong name)", "High", 7.4, A02, "CWE-295",
                "Browsers warn users and traffic can be intercepted.",
                "Install a valid certificate from a trusted authority that matches the host name.");
        rule("cors", "CORS reflects any origin and allows credentials", "High", 7.4, A05, "CWE-942",
                "Other websites can read logged-in users' data from this site.",
                "Allow only a fixed list of trusted origins; never combine reflected origins with credentials.");
        rule("csrf", "POST form without anti-CSRF token", "Medium", 5.4, A01, "CWE-352",
                "A malicious page may submit this form on behalf of a logged-in user.",
                "Add per-session CSRF tokens and SameSite=Lax/Strict cookies.");
        rule("lib", "Outdated jQuery library with known vulnerabilities", "Medium", 6.1, A06, "CWE-1104",
                "Old jQuery versions have known cross-site scripting bugs.",
                "Upgrade to a maintained jQuery 3.5+ release and track dependencies.");
        rule("http", "Site served over HTTP (no encryption)", "Medium", 5.9, A02, "CWE-319",
                "Traffic can be read or changed by anyone on the network.",
                "Enable HTTPS and redirect all HTTP traffic to it.");
        rule("mixed", "Mixed content: HTTPS page loads HTTP scripts or frames", "Medium", 4.8, A02, "CWE-311",
                "Attackers can replace the insecure resource and take over the page.",
                "Load every script, stylesheet and frame over HTTPS.");
        rule("dir", "Directory listing enabled", "Medium", 5.3, A05, "CWE-548",
                "Visitors can browse and download files that were not meant to be public.",
                "Disable directory indexing on the web server.");
        rule("phpinfo", "phpinfo() page exposed", "Medium", 5.3, A05, "CWE-200",
                "Reveals server paths, modules and configuration useful for attacks.",
                "Delete the phpinfo file from production.");
        rule("status", "Web server status page exposed", "Medium", 5.3, A05, "CWE-200",
                "Reveals internal requests and server details.",
                "Restrict /server-status to trusted addresses.");
        rule("tlsexp", "TLS certificate expires soon", "Medium", 4.0, A02, "CWE-298",
                "When it expires, visitors will see security warnings.",
                "Renew the certificate and enable automatic renewal.");
        rule("csp", "Missing Content-Security-Policy header", "Medium", 5.3, A05, "CWE-693",
                "Makes cross-site scripting easier to exploit.",
                "Add a CSP that limits script, style and frame sources.");
        rule("cookie", "Cookie missing HttpOnly / Secure / SameSite", "Medium", 5.0, A05, "CWE-1004",
                "Cookies may be stolen by scripts or sent over insecure connections.",
                "Set HttpOnly, Secure and SameSite on session cookies.");
        rule("hsts", "Missing HSTS header", "Medium", 4.8, A02, "CWE-319",
                "Browsers may still try insecure HTTP connections first.",
                "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.");
        rule("redir", "Open redirect", "Medium", 4.7, A01, "CWE-601",
                "Attackers can send users to a fake site through a trusted link.",
                "Allow-list redirect targets or use relative paths only.");
        rule("cors2", "CORS reflects arbitrary Origin (no credentials)", "Low", 3.7, A05, "CWE-942",
                "Other websites can read public responses; risky if data later becomes private.",
                "Allow only a fixed list of trusted origins.");
        rule("xfo", "Clickjacking: no X-Frame-Options / frame-ancestors", "Low", 4.3, A05, "CWE-1021",
                "The site can be embedded in a hidden frame to trick users into clicking.",
                "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.");
        rule("err", "Verbose error / stack trace shown", "Low", 3.7, A05, "CWE-209",
                "Error details help attackers learn how the application works.",
                "Show generic errors to users and log details on the server.");
        rule("srv", "Server technology/version disclosure", "Low", 3.1, A05, "CWE-200",
                "Version banners help attackers choose known exploits.",
                "Hide version banners (Server, X-Powered-By) and keep software updated.");
        rule("apidocs", "API documentation publicly accessible", "Low", 3.7, A05, "CWE-200",
                "Gives attackers a complete map of the API.",
                "Restrict API documentation to internal users or non-production systems.");
        rule("mail", "External email addresses in page source", "Info", 0, A05, "CWE-200",
                "May be harvested for spam or phishing.",
                "Review whether these addresses need to be public.");
        rule("xcto", "Missing X-Content-Type-Options", "Info", 2.0, A05, "CWE-693",
                "Browsers may guess content types, which can enable some attacks.",
                "Add X-Content-Type-Options: nosniff.");
        rule("blocked", "Scan may be incomplete: many requests were blocked", "Info", 0, A05, "CWE-693",
                "A firewall or rate limit answered with HTTP 403/429, so some pages were not really tested.",
                "Ask the client to allow the tester's address, then run the scan again.");
    }

    // ---------------------------------------------------------------- patterns
    static final Pattern SQL_ERR = Pattern.compile(
            "(SQL syntax.{0,40}MySQL|SQLSTATE\\[|ORA-\\d{5}|PostgreSQL.{0,30}ERROR|SQLite.{0,20}(error|Exception)|unclosed quotation mark|SQLITE_ERROR|mysqli?_)",
            Pattern.CASE_INSENSITIVE);
    static final Pattern STACK = Pattern.compile(
            "(at [\\w.$]+\\([\\w.]+:\\d+\\)|Traceback \\(most recent call last\\)|Stack trace:|Exception in thread|at Object\\.\\w+ \\()");
    static final Pattern STRONG = Pattern.compile(
            "(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\\-]{35}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[0-9a-zA-Z]{24,})");
    static final Pattern WEAK = Pattern.compile("(?i:api[_-]?key|secret|token)\\s*[:=]\\s*['\"][A-Za-z0-9_\\-]{16,}['\"]");
    static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    static final Pattern JQUERY = Pattern.compile("jquery[-./@]?(\\d+)\\.(\\d+)\\.(\\d+)", Pattern.CASE_INSENSITIVE);
    static final Pattern SKIP_EXT = Pattern.compile(
            ".*\\.(jpg|jpeg|png|gif|svg|ico|webp|css|pdf|zip|gz|woff2?|ttf|mp4|mp3|js|xml)$", Pattern.CASE_INSENSITIVE);
    static final Pattern REDIR_PARAM = Pattern.compile(
            "(?i)^(url|redirect|redirect_uri|next|return|returnurl|to|dest|destination|continue)$");
    static final Pattern LOC = Pattern.compile("<loc>\\s*([^<\\s]+)\\s*</loc>", Pattern.CASE_INSENSITIVE);
    static final Pattern ENVLINE = Pattern.compile("(?m)^[A-Z][A-Z0-9_]{2,}=.+");
    static final String TOKEN_NAME = "(?i).*(csrf|token|nonce|authenticity|xsrf).*";
    static final String SEARCHY = "(?i)^(q|s|search|query|keyword|keywords|term)$";
    static final String IMAGEY = "(?i).*\\.(png|jpe?g|gif|svg|webp|css|js|woff2?)$";

    // ---------------------------------------------------------------- probes (content must match, not just status 200)
    record Resp(int status, HttpHeaders headers, String body, URI uri) {
        String h(String name) {
            return headers.firstValue(name).orElse(null);
        }

        boolean isHtml() {
            String ct = h("content-type");
            return ct != null && ct.toLowerCase(Locale.ROOT).contains("html");
        }
    }

    record Probe(String path, String rule, Predicate<Resp> test) {}

    static final Predicate<Resp> ZIP = r -> !r.isHtml() && r.body().startsWith("PK");
    static final Predicate<Resp> SQLDUMP = r -> !r.isHtml()
            && (r.body().contains("CREATE TABLE") || r.body().contains("INSERT INTO") || r.body().contains("mysqldump"));
    static final Predicate<Resp> DIRLIST = r -> r.body().contains("Index of /");
    static final Predicate<Resp> PHPINFO = r -> r.body().contains("phpinfo()") && r.body().contains("PHP Version");
    static final Predicate<Resp> OPENAPI = r -> r.body().contains("\"openapi\"") || r.body().contains("\"swagger\"");

    static final List<Probe> PROBES = List.of(
            new Probe("/.git/config", "git", r -> r.body().contains("[core]")),
            new Probe("/.env", "env", r -> !r.isHtml() && ENVLINE.matcher(r.body()).find()),
            new Probe("/backup.zip", "bak", ZIP), new Probe("/site.zip", "bak", ZIP), new Probe("/www.zip", "bak", ZIP),
            new Probe("/backup.sql", "bak", SQLDUMP), new Probe("/db.sql", "bak", SQLDUMP),
            new Probe("/dump.sql", "bak", SQLDUMP), new Probe("/database.sql", "bak", SQLDUMP),
            new Probe("/phpinfo.php", "phpinfo", PHPINFO), new Probe("/info.php", "phpinfo", PHPINFO),
            new Probe("/server-status", "status", r -> r.body().contains("Apache Server Status")),
            new Probe("/actuator/env", "actuator", r -> r.body().contains("propertySources")),
            new Probe("/swagger-ui.html", "apidocs", r -> r.body().toLowerCase(Locale.ROOT).contains("swagger")),
            new Probe("/v3/api-docs", "apidocs", OPENAPI), new Probe("/v2/api-docs", "apidocs", OPENAPI),
            new Probe("/openapi.json", "apidocs", OPENAPI),
            new Probe("/uploads/", "dir", DIRLIST), new Probe("/backup/", "dir", DIRLIST), new Probe("/files/", "dir", DIRLIST));

    // ---------------------------------------------------------------- engine
    private final Store store;
    private final ExecutorService pool = Executors.newFixedThreadPool(2);
    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(8)).build();

    @Value("${app.max-pages}")
    private int maxPages;

    public WebScanner(Store store) {
        this.store = store;
    }

    @EventListener(ApplicationReadyEvent.class)
    void onReady() {
        store.failRunning();
    }

    public void start(String engagementId, String scanId, String url, boolean active, String cookie, List<String> scope) {
        pool.submit(new Run(engagementId, scanId, url, active, cookie, scope));
    }

    // ---------------------------------------------------------------- shared helpers
    static boolean inScope(List<String> scope, String h) {
        if (h == null) return false;
        String host = h.toLowerCase(Locale.ROOT);
        for (String s : scope) if (host.equals(s) || host.endsWith("." + s)) return true;
        return false;
    }

    static boolean blocked(InetAddress a) {
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isSiteLocalAddress()
                || a.isLinkLocalAddress() || a.isMulticastAddress()) return true;
        byte[] b = a.getAddress();
        if (b.length == 4) {
            int b0 = b[0] & 255, b1 = b[1] & 255;
            if (b0 == 0) return true;
            if (b0 == 100 && b1 >= 64 && b1 <= 127) return true; // carrier-grade NAT range
        }
        return b.length == 16 && (b[0] & 0xfe) == 0xfc;             // IPv6 unique-local fc00::/7
    }

    static void checkPublic(String host) throws UnknownHostException {
        for (InetAddress a : InetAddress.getAllByName(host))
            if (blocked(a)) throw new IllegalArgumentException("Private or local addresses cannot be scanned.");
    }

    /** Used by the API before a scan starts. Throws IllegalArgumentException with a readable message. */
    public static URI validateTarget(String url, List<String> scope) {
        URI u;
        try {
            u = URI.create(url.trim());
        } catch (Exception e) {
            throw new IllegalArgumentException("That is not a valid URL.");
        }
        String sc = u.getScheme();
        if (sc == null || !(sc.equals("http") || sc.equals("https")))
            throw new IllegalArgumentException("Only http:// or https:// URLs are allowed.");
        if (u.getHost() == null) throw new IllegalArgumentException("The URL has no host name.");
        if (!inScope(scope, u.getHost()))
            throw new IllegalArgumentException(u.getHost() + " is not in this engagement's scope.");
        try {
            checkPublic(u.getHost());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Cannot resolve " + u.getHost());
        }
        return u;
    }

    static String cut(String s, int n) {
        if (s == null) return "";
        return s.length() > n ? s.substring(0, n) + "..." : s;
    }

    static String mask(String s) {
        return s.length() > 8 ? s.substring(0, 4) + "************" : "********";
    }

    static String path(URI u) {
        String p = u.getRawPath();
        return (p == null || p.isEmpty()) ? "/" : p;
    }

    static String hostOf(URI u) {
        return u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
    }

    /** Page "shape": path plus parameter names, so ?id=1 and ?id=2 are treated as one page. */
    static String shape(URI u) {
        String base = u.getScheme() + "://" + u.getRawAuthority() + path(u);
        String q = u.getRawQuery();
        if (q == null) return base;
        List<String> names = new ArrayList<>();
        for (String p : q.split("&")) names.add(p.split("=", 2)[0]);
        Collections.sort(names);
        return base + "?" + String.join("&", names);
    }

    static URI withParam(URI u, String name, String value) {
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
        return URI.create(u.getScheme() + "://" + u.getRawAuthority() + path(u) + "?" + String.join("&", out));
    }

    static String queryValue(URI u, String name) {
        String q = u.getRawQuery();
        if (q == null) return "test";
        for (String pair : q.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv[0].equals(name)) return kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
        }
        return "test";
    }

    static int rank(String c) {
        return "High".equals(c) ? 3 : "Medium".equals(c) ? 2 : 1;
    }

    /** All hits of one rule inside one scan. */
    static final class Agg {
        String conf;
        int n;
        final Set<String> loc = new LinkedHashSet<>();
        final List<String> ev = new ArrayList<>();

        Agg(String conf) {
            this.conf = conf;
        }
    }

    // ---------------------------------------------------------------- one scan
    private final class Run implements Runnable {
        final String eng, scan, url, cookie;
        final boolean active;
        final List<String> scope;
        final StringBuilder log = new StringBuilder();
        long lastFlush = 0;
        final Map<String, Agg> found = new LinkedHashMap<>();
        final Set<String> pages = new LinkedHashSet<>();
        final Set<String> cookiesSeen = new HashSet<>();
        final Set<String> emails = new LinkedHashSet<>();
        final Deque<URI> queue = new ArrayDeque<>();
        final Set<String> seen = new HashSet<>();
        final List<URI> targets = new ArrayList<>();
        URI base;
        String host = "";
        boolean https;
        int blockedCount = 0;
        int scriptsFetched = 0;

        Run(String eng, String scan, String url, boolean active, String cookie, List<String> scope) {
            this.eng = eng;
            this.scan = scan;
            this.url = url;
            this.active = active;
            this.cookie = cookie;
            this.scope = scope;
        }

        void say(String m) {
            log.append(m).append('\n');
            long now = System.currentTimeMillis();
            if (now - lastFlush > 1500) {
                lastFlush = now;
                store.setLog(scan, log.toString());
            }
        }

        void pause(long ms) {
            try {
                Thread.sleep(ms);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        void add(String id, String conf, String where, String evidence) {
            Agg a = found.computeIfAbsent(id, k -> new Agg(conf));
            if (rank(conf) > rank(a.conf)) a.conf = conf;
            a.n++;
            if (a.loc.size() < 25) a.loc.add(where);
            String e = cut(evidence, 300);
            if (a.ev.size() < 5 && !a.ev.contains(e)) a.ev.add(e);
        }

        void guard(URI u) {
            String sc = u.getScheme();
            if (sc == null || !(sc.equals("http") || sc.equals("https")))
                throw new IllegalArgumentException("Only http/https is allowed");
            if (!inScope(scope, u.getHost())) throw new IllegalArgumentException("Out of scope: " + u.getHost());
            try {
                checkPublic(u.getHost());
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Cannot resolve " + u.getHost());
            }
        }

        Resp get(URI start, boolean follow, String origin) throws Exception {
            URI cur = start;
            for (int i = 0; i < 5; i++) {
                guard(cur);
                HttpRequest.Builder b = HttpRequest.newBuilder(cur).timeout(Duration.ofSeconds(10))
                        .header("User-Agent", "SecScanPro/2.0 (authorized security assessment)").GET();
                if (cookie != null && !cookie.isBlank()) b.header("Cookie", cookie);
                if (origin != null) b.header("Origin", origin);
                HttpResponse<InputStream> r = http.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
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
            throw new IOException("Too many redirects");
        }

        @Override
        public void run() {
            try {
                base = URI.create(url);
                guard(base);
                say("Target " + url + " | mode: " + (active ? "passive + active tests" : "passive only"));
                say("In-scope hosts: " + String.join(", ", scope));
                if ("https".equals(base.getScheme())) {
                    say("PHASE 1 TLS certificate");
                    tls();
                }
                say("PHASE 2 Crawl and passive checks");
                Resp first;
                try {
                    first = get(base, true, null);
                } catch (Exception ex) {
                    throw new IllegalStateException("The start URL could not be reached (" + ex.getClass().getSimpleName() + ")");
                }
                base = first.uri();
                host = hostOf(base);
                https = "https".equals(base.getScheme());
                if (!https) add("http", "High", "/ (site-wide)", "The site is served over http:// (final URL " + base + ")");
                headers(first);
                crawl(first);
                cors();
                probes();
                if (active) activeTests();
                else say("PHASE 4 Active tests skipped (passive mode)");
                finish();
            } catch (Throwable t) {
                say("FAILED: " + t.getMessage());
                store.finishScan(scan, "FAILED", pages.size(), log.toString());
            }
        }

        // ---- TLS
        void tls() {
            String h = base.getHost();
            int port = base.getPort() > 0 ? base.getPort() : 443;
            try (SSLSocket s = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
                s.connect(new InetSocketAddress(h, port), 8000);
                s.setSoTimeout(8000);
                SSLParameters sp = s.getSSLParameters();
                sp.setEndpointIdentificationAlgorithm("HTTPS");
                sp.setServerNames(List.of(new SNIHostName(h)));
                s.setSSLParameters(sp);
                s.startHandshake();
                X509Certificate c = (X509Certificate) s.getSession().getPeerCertificates()[0];
                long days = Duration.between(Instant.now(), c.getNotAfter().toInstant()).toDays();
                say("  TLS ok: " + s.getSession().getProtocol() + ", certificate valid for " + days + " more days");
                if (days < 30) add("tlsexp", "High", "TLS certificate", "Certificate expires in " + days + " days (" + c.getNotAfter() + ")");
            } catch (SSLException e) {
                say("  TLS problem: " + cut(e.getMessage(), 120));
                add("tls", "High", "TLS handshake with " + h, cut(e.getMessage(), 200));
            } catch (Exception e) {
                say("  TLS check skipped (" + e.getClass().getSimpleName() + ")");
            }
        }

        // ---- headers (first response only, labelled honestly)
        void headers(Resp r) {
            String where = "Home page response headers";
            String csp = r.h("content-security-policy");
            if (csp == null) add("csp", "High", where, "Header 'Content-Security-Policy' is not present");
            if (r.h("x-frame-options") == null && (csp == null || !csp.contains("frame-ancestors")))
                add("xfo", "High", where, "Neither X-Frame-Options nor CSP frame-ancestors is set");
            if (r.h("x-content-type-options") == null)
                add("xcto", "High", where, "Header 'X-Content-Type-Options: nosniff' is not present");
            if (https && r.h("strict-transport-security") == null)
                add("hsts", "High", where, "Header 'Strict-Transport-Security' is not present");
            String sv = r.h("server"), xp = r.h("x-powered-by");
            if ((sv != null && sv.matches(".*\\d+\\.\\d+.*")) || xp != null)
                add("srv", "High", where, "Server: " + sv + (xp != null ? " | X-Powered-By: " + xp : ""));
        }

        void cookieCheck(String c) {
            String name = c.split("=", 2)[0].trim();
            if (!cookiesSeen.add(name)) return;
            String lc = c.toLowerCase(Locale.ROOT);
            List<String> miss = new ArrayList<>();
            if (!lc.contains("httponly")) miss.add("HttpOnly");
            if (https && !lc.contains("secure")) miss.add("Secure");
            if (!lc.contains("samesite")) miss.add("SameSite");
            if (miss.isEmpty()) return;
            boolean sessionLike = name.matches("(?i).*(sess|sid|auth|token|jwt|login|user).*");
            add("cookie", sessionLike ? "High" : "Low", "Set-Cookie: " + name, name + " is missing: " + String.join(", ", miss));
        }

        // ---- crawl
        boolean okLink(URI nu) {
            String sc = nu.getScheme();
            return sc != null && (sc.equals("http") || sc.equals("https")) && hostOf(nu).equals(host)
                    && !SKIP_EXT.matcher(path(nu)).matches();
        }

        void seedSitemap() {
            try {
                Resp r = get(base.resolve("/sitemap.xml"), true, null);
                if (r.status() != 200) return;
                Matcher m = LOC.matcher(r.body());
                int n = 0;
                while (m.find() && n < maxPages * 2) {
                    URI u = URI.create(m.group(1).trim());
                    if (okLink(u) && seen.add(shape(u))) {
                        queue.add(u);
                        n++;
                    }
                }
                say("  sitemap.xml: " + n + " URLs added to the crawl");
            } catch (Exception ignored) {
                // no sitemap or unreadable: fine
            }
        }

        void crawl(Resp first) {
            seen.add(shape(base));
            page(base, first);
            seedSitemap();
            while (!queue.isEmpty() && pages.size() < maxPages) {
                URI cur = queue.poll();
                Resp r;
                try {
                    r = get(cur, true, null);
                } catch (Exception ex) {
                    say("  could not open " + path(cur) + " (" + ex.getClass().getSimpleName() + ")");
                    continue;
                }
                page(cur, r);
                pause(100);
            }
            say("Crawl finished: " + pages.size() + " pages, " + targets.size() + " URLs with parameters");
        }

        void page(URI cur, Resp r) {
            String pg = path(cur) + (cur.getRawQuery() != null ? "?" + cut(cur.getRawQuery(), 40) : "");
            pages.add(pg);
            say("  crawled " + pg + " [" + r.status() + "]");
            if (r.status() == 403 || r.status() == 429) blockedCount++;
            for (String c : r.headers().allValues("set-cookie")) cookieCheck(c);

            String body = r.body();
            Matcher st = STACK.matcher(body);
            if (st.find()) add("err", "Medium", pg, "Page contains: " + cut(st.group(), 120));
            if (body.contains("Index of /")) add("dir", "High", pg, "Response contains 'Index of /' (directory listing)");
            secretScan(body, pg);
            Matcher em = EMAIL.matcher(body);
            while (em.find()) {
                String addr = em.group();
                String d = addr.substring(addr.indexOf('@') + 1).toLowerCase(Locale.ROOT);
                String root = host.startsWith("www.") ? host.substring(4) : host;
                boolean sameSite = d.equals(root) || d.endsWith("." + root) || root.endsWith("." + d);
                if (!sameSite && !d.matches(IMAGEY)) emails.add(addr);
            }
            if (!r.isHtml()) return;

            Document doc = Jsoup.parse(body, cur.toString());
            for (Element s : doc.select("script[src]")) {
                String src = s.absUrl("src");
                Matcher jm = JQUERY.matcher(src);
                if (jm.find()) {
                    try {
                        int maj = Integer.parseInt(jm.group(1)), min = Integer.parseInt(jm.group(2));
                        if (maj < 3 || (maj == 3 && min < 5))
                            add("lib", "High", pg, "jQuery " + jm.group(1) + "." + jm.group(2) + "." + jm.group(3) + " (src: " + cut(src, 120) + ")");
                    } catch (NumberFormatException ignored) {
                        // not a real version number
                    }
                }
                try {
                    URI su = URI.create(src);
                    if (hostOf(su).equals(host) && scriptsFetched < 8) {
                        scriptsFetched++;
                        secretScan(get(su, true, null).body(), path(su));
                    }
                } catch (Exception ignored) {
                    // script could not be read: skip
                }
            }
            if (https) {
                for (Element e : doc.select("script[src],iframe[src],link[href]")) {
                    boolean isLink = e.tagName().equals("link");
                    if (isLink && !e.attr("rel").toLowerCase(Locale.ROOT).contains("stylesheet")) continue;
                    String u = isLink ? e.absUrl("href") : e.absUrl("src");
                    if (u.startsWith("http://")) add("mixed", "High", pg, "<" + e.tagName() + "> loads " + cut(u, 100));
                }
            }
            for (Element form : doc.select("form")) formCheck(form, cur, pg);
            for (Element a : doc.select("a[href]")) {
                String h = a.absUrl("href");
                int hash = h.indexOf('#');
                if (hash >= 0) h = h.substring(0, hash);
                if (h.isEmpty()) continue;
                try {
                    URI nu = URI.create(h);
                    if (!okLink(nu)) continue;
                    if (active && nu.getRawQuery() != null && targets.size() < 15
                            && targets.stream().noneMatch(t -> path(t).equals(path(nu)))) targets.add(nu);
                    if (seen.size() < maxPages * 4 && seen.add(shape(nu))) queue.add(nu);
                } catch (Exception ignored) {
                    // bad link: skip
                }
            }
        }

        void secretScan(String body, String where) {
            Matcher s1 = STRONG.matcher(body);
            if (s1.find()) {
                add("key", "High", where, "Found: " + mask(s1.group()));
                return;
            }
            Matcher s2 = WEAK.matcher(body);
            if (s2.find()) add("key", "Low", where, "Possible secret assignment: " + mask(s2.group()));
        }

        void formCheck(Element form, URI cur, String pg) {
            String method = form.attr("method").toLowerCase(Locale.ROOT);
            String action = form.absUrl("action").isEmpty() ? cur.toString() : form.absUrl("action");
            boolean hasPw = !form.select("input[type=password]").isEmpty();
            if (hasPw && (!"https".equals(cur.getScheme()) || action.startsWith("http://")))
                add("pwhttp", "High", pg, "<form action=\"" + cut(form.attr("action"), 80) + "\"> has a password field and is not protected by HTTPS");
            if (method.equals("post")) {
                boolean token = false;
                for (Element in : form.select("input[type=hidden]"))
                    if (in.attr("name").matches(TOKEN_NAME)) token = true;
                boolean searchOnly = true;
                for (Element in : form.select("input[type=text],input[type=email],input[type=tel],input[type=number],textarea,input:not([type])"))
                    if (!in.attr("name").matches(SEARCHY)) searchOnly = false;
                if (!token && (hasPw || !searchOnly))
                    add("csrf", hasPw ? "Medium" : "Low", pg,
                            "<form method=\"POST\" action=\"" + cut(form.attr("action"), 80) + "\"> has no hidden field named like csrf/token");
            } else if (active) {
                try {
                    URI au = URI.create(action);
                    for (Element in : form.select("input[type=text],input[type=search],input:not([type])")) {
                        String n = in.attr("name");
                        if (!n.isEmpty()) au = withParam(au, n, "test");
                    }
                    if (au.getRawQuery() != null && hostOf(au).equals(host) && targets.size() < 15) targets.add(au);
                } catch (Exception ignored) {
                    // unusable form action: skip
                }
            }
        }

        // ---- CORS
        void cors() {
            String evil = "https://secscan-test.example";
            try {
                Resp r = get(base, true, evil);
                String ao = r.h("access-control-allow-origin"), ac = r.h("access-control-allow-credentials");
                if (evil.equals(ao)) {
                    if ("true".equalsIgnoreCase(ac))
                        add("cors", "High", "/ (CORS)", "Origin " + evil + " was reflected together with Access-Control-Allow-Credentials: true");
                    else add("cors2", "High", "/ (CORS)", "Origin " + evil + " was reflected in Access-Control-Allow-Origin");
                }
            } catch (Exception ignored) {
                // CORS test skipped
            }
        }

        // ---- sensitive files
        void probes() {
            say("PHASE 3 Sensitive files and exposed interfaces");
            String origin = base.getScheme() + "://" + base.getRawAuthority();
            for (Probe p : PROBES) {
                try {
                    Resp r = get(URI.create(origin + p.path()), true, null);
                    boolean hit = r.status() == 200 && p.test().test(r);
                    say("  " + p.path() + (hit ? "  -> ISSUE" : "  ok"));
                    if (hit) add(p.rule(), "High", p.path(), "GET " + p.path() + " returned HTTP 200 and the content matches a known signature");
                } catch (Exception ex) {
                    say("  " + p.path() + "  (not reachable)");
                }
                pause(150);
            }
        }

        // ---- active tests with harmless inputs
        void activeTests() {
            say("PHASE 4 Active tests with harmless inputs (" + targets.size() + " URLs)");
            String marker = "ss" + Long.toHexString(System.nanoTime() & 0xffffffL);
            for (URI t : targets) {
                String q = t.getRawQuery() == null ? "" : t.getRawQuery();
                for (String pair : q.split("&")) {
                    String name = pair.split("=", 2)[0];
                    if (name.isEmpty()) continue;
                    String where = path(t) + "?" + name + "=";
                    try {
                        Resp x = get(withParam(t, name, marker + "<\"'"), true, null);
                        if (x.isHtml() && x.body().contains(marker + "<\""))
                            add("xss", "High", where, "Parameter '" + name + "' was returned unescaped: " + marker + "<\"'");
                        pause(150);
                        Resp b0 = get(t, true, null);
                        Resp y = get(withParam(t, name, queryValue(t, name) + "'"), true, null);
                        Matcher m = SQL_ERR.matcher(y.body());
                        if (m.find() && !SQL_ERR.matcher(b0.body()).find())
                            add("sqli", "High", where, "Adding a quote caused a database error: " + cut(m.group(), 100));
                        if (STACK.matcher(y.body()).find() && !STACK.matcher(b0.body()).find())
                            add("err", "High", where, "A quote in the input caused a stack trace");
                        pause(150);
                        if (REDIR_PARAM.matcher(name).matches()) {
                            Resp z = get(withParam(t, name, "https://example.org/"), false, null);
                            String loc = z.h("location");
                            if (z.status() >= 300 && z.status() < 400 && loc != null && loc.startsWith("https://example.org"))
                                add("redir", "High", where, "?" + name + "=https://example.org/ gave HTTP " + z.status() + " Location: " + loc);
                        }
                    } catch (Exception ex) {
                        say("  skipped " + where + " (" + ex.getClass().getSimpleName() + ")");
                    }
                }
                say("  tested " + path(t));
            }
        }

        // ---- save
        void finish() {
            if (emails.size() >= 3) {
                StringBuilder sb = new StringBuilder("Found " + emails.size() + " unique external addresses, e.g. ");
                int k = 0;
                for (String e : emails) {
                    if (k++ == 3) break;
                    sb.append(e.charAt(0)).append("***").append(e.substring(e.indexOf('@'))).append(' ');
                }
                add("mail", "Medium", "Multiple pages", sb.toString().trim());
            }
            if (blockedCount > 0 && blockedCount * 2 >= Math.max(1, pages.size()))
                add("blocked", "High", "Crawl", "HTTP 403/429 on " + blockedCount + " of " + pages.size() + " requests");

            say("PHASE 5 Saving results");
            int n = 0;
            for (Map.Entry<String, Agg> en : found.entrySet()) {
                Rule r = R.get(en.getKey());
                Agg a = en.getValue();
                store.addFinding(eng, scan, "AUTO", en.getKey(), r.title(), r.sev(), a.conf, r.cvss(), r.owasp(), r.cwe(),
                        String.join("\n", a.loc), a.n, String.join("\n", a.ev), r.why(), r.fix());
                n++;
            }
            say("DONE: " + pages.size() + " pages, " + n + " findings (grouped by type)");
            store.finishScan(scan, "DONE", pages.size(), log.toString());
        }
    }
}
