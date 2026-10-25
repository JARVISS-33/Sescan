package com.secscan;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.util.HtmlUtils;

/** Risk score and the printable client report. */
public final class Report {
    private Report() {}

    static final Map<String, Integer> W = Map.of("Critical", 25, "High", 12, "Medium", 5, "Low", 2, "Info", 0);
    static final Map<String, Double> C = Map.of("High", 1.0, "Medium", 0.7, "Low", 0.4);
    static final List<String> ORDER = List.of("Critical", "High", "Medium", "Low", "Info");

    static String str(Map<String, Object> m, String k) {
        Object o = m.get(k);
        return o == null ? "" : String.valueOf(o);
    }

    static String h(String s) {
        return HtmlUtils.htmlEscape(s == null ? "" : s);
    }

    /** Only Open and Confirmed findings count towards risk. */
    static boolean counts(Map<String, Object> f) {
        String s = str(f, "status");
        return s.equals("Open") || s.equals("Confirmed");
    }

    /**
     * Penalty for one finding. Each finding is already one rule per scan (pages are grouped inside it), so a
     * problem repeated on 25 pages costs the same as on 1 page. Low-confidence automatic results weigh less;
     * findings a tester confirmed, and manual findings, weigh fully.
     */
    static double penalty(Map<String, Object> f) {
        double w = W.getOrDefault(str(f, "severity"), 0);
        boolean verified = str(f, "status").equals("Confirmed") || str(f, "source").equals("MANUAL");
        return w * (verified ? 1.0 : C.getOrDefault(str(f, "confidence"), 0.7));
    }

    public static int score(List<Map<String, Object>> fs) {
        double p = 0;
        for (Map<String, Object> f : fs) if (counts(f)) p += penalty(f);
        return (int) Math.max(0, Math.round(100 - p));
    }

    public static String grade(int s) {
        return s >= 90 ? "A" : s >= 80 ? "B" : s >= 65 ? "C" : s >= 50 ? "D" : "F";
    }

    public static String html(Map<String, Object> e, List<Map<String, Object>> scans, List<Map<String, Object>> all) {
        List<Map<String, Object>> shown = new ArrayList<>();
        int falsePositives = 0;
        for (Map<String, Object> f : all) {
            if (str(f, "status").equals("False positive")) falsePositives++;
            else shown.add(f);
        }
        int score = score(all);
        Map<String, Integer> cnt = new LinkedHashMap<>();
        for (String s : ORDER) cnt.put(s, 0);
        int open = 0;
        for (Map<String, Object> f : shown) {
            if (counts(f)) {
                cnt.merge(str(f, "severity"), 1, Integer::sum);
                open++;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Security Assessment Report - ")
          .append(h(str(e, "client"))).append("</title><style>")
          .append("body{font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#1b1f2a}")
          .append("h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;border-bottom:2px solid #dde;padding-bottom:4px;margin-top:28px}")
          .append(".meta{color:#555;font-size:13px}table{border-collapse:collapse;width:100%;margin:8px 0}")
          .append("td,th{border:1px solid #dde;padding:6px 10px;text-align:left;font-size:13px}th{background:#f1f3f5}")
          .append(".score{font-size:44px;font-weight:700;margin:0}.sv{color:#fff;padding:1px 9px;border-radius:5px;font-size:12px;font-weight:700}")
          .append(".Critical{background:#c92a2a}.High{background:#e8590c}.Medium{background:#f08c00}.Low{background:#1c7ed6}.Info{background:#868e96}")
          .append(".f{border:1px solid #dde;border-radius:8px;padding:10px 14px;margin:12px 0;break-inside:avoid}")
          .append("pre{background:#f1f3f5;padding:8px;white-space:pre-wrap;word-break:break-word;border-radius:6px;font-size:12px;margin:4px 0}")
          .append("@media print{body{margin:0;max-width:none}h2{break-after:avoid}}</style></head><body>");

        sb.append("<h1>Security Assessment Report</h1><div class=\"meta\">Client: <b>").append(h(str(e, "client")))
          .append("</b> &middot; Authorization reference: <b>").append(h(str(e, "auth_ref")))
          .append("</b><br>Prepared by: ").append(h(str(e, "tester").isEmpty() ? "Security testing team" : str(e, "tester")))
          .append(" &middot; Report date: ").append(LocalDate.now()).append("</div>");

        sb.append("<h2>1. Executive summary</h2><p class=\"score\">").append(score).append("/100 &nbsp;<span style=\"font-size:20px\">Grade ")
          .append(grade(score)).append("</span></p>");
        if (open == 0) {
            sb.append("<p>No open issues were identified by the tests performed within the agreed scope.</p>");
        } else {
            sb.append("<p>").append(open).append(open == 1 ? " open issue was" : " open issues were")
              .append(" identified within the agreed scope. Issues rated Critical or High should be fixed first.</p>");
        }
        sb.append("<table><tr>");
        for (String s : ORDER) sb.append("<th>").append(s).append("</th>");
        sb.append("</tr><tr>");
        for (String s : ORDER) sb.append("<td>").append(cnt.get(s)).append("</td>");
        sb.append("</tr></table>");
        sb.append("<p class=\"meta\">The score starts at 100 and subtracts a weighted penalty for each open or confirmed finding "
                + "(Critical 25, High 12, Medium 5, Low 2). Each type of issue counts once, however many pages it appears on, and "
                + "automatic results with low confidence count less until a tester confirms them.</p>");

        sb.append("<h2>2. Scope and activities</h2><p><b>In-scope assets:</b></p><pre>").append(h(str(e, "scope"))).append("</pre>");
        if (!scans.isEmpty()) {
            sb.append("<table><tr><th>Test</th><th>Target</th><th>Status</th><th>Pages</th><th>Date</th></tr>");
            for (Map<String, Object> s : scans) {
                sb.append("<tr><td>").append(h(str(s, "kind"))).append("</td><td>").append(h(str(s, "target")))
                  .append("</td><td>").append(h(str(s, "status"))).append("</td><td>").append(h(str(s, "pages")))
                  .append("</td><td>").append(h(str(s, "created_at").length() >= 10 ? str(s, "created_at").substring(0, 10) : ""))
                  .append("</td></tr>");
            }
            sb.append("</table>");
        }

        sb.append("<h2>3. Findings</h2>");
        if (shown.isEmpty()) sb.append("<p>No findings recorded.</p>");
        int i = 0;
        for (Map<String, Object> f : shown) {
            i++;
            String sev = str(f, "severity");
            sb.append("<div class=\"f\"><span class=\"sv ").append(h(sev)).append("\">").append(h(sev)).append("</span> <b>F-")
              .append(String.format("%02d", i)).append(" &middot; ").append(h(str(f, "title"))).append("</b>")
              .append("<div class=\"meta\">Status: ").append(h(str(f, "status")))
              .append(" &middot; CVSS (estimated): ").append(h(str(f, "cvss")))
              .append(" &middot; Confidence: ").append(h(str(f, "confidence")))
              .append(" &middot; Source: ").append(str(f, "source").equals("MANUAL") ? "Manual testing" : "Automated scan");
            if (!str(f, "owasp").isEmpty()) sb.append(" &middot; ").append(h(str(f, "owasp")));
            if (!str(f, "cwe").isEmpty()) sb.append(" &middot; ").append(h(str(f, "cwe")));
            if (!str(f, "occurrences").isEmpty() && !str(f, "occurrences").equals("1"))
                sb.append(" &middot; Seen ").append(h(str(f, "occurrences"))).append(" times");
            sb.append("</div>");
            if (!str(f, "location").isEmpty()) sb.append("<p><b>Affected location(s)</b></p><pre>").append(h(str(f, "location"))).append("</pre>");
            if (!str(f, "description").isEmpty()) sb.append("<p><b>Description / impact</b><br>").append(h(str(f, "description"))).append("</p>");
            if (!str(f, "evidence").isEmpty()) sb.append("<p><b>Evidence</b></p><pre>").append(h(str(f, "evidence"))).append("</pre>");
            if (!str(f, "fix").isEmpty()) sb.append("<p><b>Recommendation</b><br>").append(h(str(f, "fix"))).append("</p>");
            if (!str(f, "notes").isEmpty()) sb.append("<p><b>Tester notes</b><br>").append(h(str(f, "notes"))).append("</p>");
            sb.append("</div>");
        }
        if (falsePositives > 0)
            sb.append("<p class=\"meta\">").append(falsePositives).append(" automatic result(s) were reviewed and excluded as false positives.</p>");

        sb.append("<h2>4. Methodology and limitations</h2><p>Testing combined automated checks with tester review. Automated checks "
                + "include: transport security and certificate checks, security headers, cookie flags, crawling of linked pages "
                + "and the sitemap, content checks for exposed secrets and error messages, probes for commonly exposed files and "
                + "admin interfaces, and (when enabled) harmless test inputs for injection and redirect issues.</p>"
                + "<p>Limitations: automated testing cannot find every vulnerability, only reachable pages up to the crawl limit were "
                + "tested, areas behind a login are covered only when a session was supplied, and business-logic and access-control "
                + "flaws need manual testing. A good score is not a guarantee that the system is secure.</p>");
        sb.append("</body></html>");
        return sb.toString();
    }
}
