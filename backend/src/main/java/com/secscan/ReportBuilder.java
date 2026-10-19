package com.secscan;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.web.util.HtmlUtils;

/** Builds the downloadable HTML report from a finished scan. */
public final class ReportBuilder {
    private ReportBuilder() {}

    private static String esc(String s) {
        return HtmlUtils.htmlEscape(s == null ? "" : s);
    }

    public static String html(ScanEntity e, JsonNode result) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Security report</title>")
          .append("<style>body{font:14px system-ui,sans-serif;max-width:820px;margin:24px auto;padding:0 14px;color:#1b1f2a}")
          .append("h1{margin-bottom:4px}.sc{font-size:42px;font-weight:700}.sv{color:#fff;padding:1px 8px;border-radius:5px;font-size:12px}")
          .append(".Critical{background:#c92a2a}.High{background:#e8590c}.Medium{background:#f08c00}.Low{background:#1c7ed6}.Info{background:#868e96}")
          .append("pre{background:#f1f3f5;padding:8px;white-space:pre-wrap;border-radius:6px}.f{border:1px solid #dde;border-radius:8px;padding:10px 14px;margin:10px 0}</style></head><body>");
        sb.append("<h1>Security Scan Report</h1>");
        sb.append("<p><b>Target:</b> ").append(esc(e.url)).append("<br><b>Date:</b> ").append(e.createdAt)
          .append("<br><b>Pages scanned:</b> ").append(e.pagesCount).append("</p>");
        sb.append("<div class=\"sc\">").append(e.score).append("/100 &nbsp; Grade ").append(esc(e.grade)).append("</div><hr>");
        JsonNode cov = result.get("coverage");
        if (cov != null) {
            sb.append("<p><b>Coverage:</b> ").append(cov.path("pagesCrawled").asInt()).append(" pages, ")
              .append(cov.path("formsFound").asInt()).append(" forms, ")
              .append(cov.path("parametersTested").asInt()).append(" parameters tested with active checks</p>");
            JsonNode w = cov.get("warnings");
            if (w != null && !w.isEmpty()) {
                sb.append("<div class=\"f\"><b>Scan incomplete - treat the score with caution:</b><ul>");
                for (JsonNode x : w) sb.append("<li>").append(esc(x.asText())).append("</li>");
                sb.append("</ul></div>");
            }
        }
        JsonNode findings = result.get("findings");
        if (findings == null || findings.isEmpty()) sb.append("<p>No issues found by the implemented checks.</p>");
        else for (JsonNode f : findings) {
            sb.append("<div class=\"f\"><span class=\"sv ").append(esc(f.get("severity").asText())).append("\">")
              .append(esc(f.get("severity").asText())).append("</span> <b>").append(esc(f.get("title").asText())).append("</b>")
              .append("<p>CVSS ").append(f.get("cvss").asText()).append(" &middot; OWASP ").append(esc(f.get("owasp").asText()))
              .append(" &middot; ").append(esc(f.get("cwe").asText())).append("<br>Page: ").append(esc(f.get("page").asText())).append("</p>")
              .append("<pre>").append(esc(f.get("evidence").asText())).append("</pre>")
              .append("<p><b>How to fix:</b> ").append(esc(f.get("fix").asText())).append("</p></div>");
        }
        sb.append("<p><i>Automated scan by SecScan Studio. Automated tools cannot find every vulnerability; ")
          .append("use this report as a starting point.</i></p></body></html>");
        return sb.toString();
    }
}
