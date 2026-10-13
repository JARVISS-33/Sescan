package com.secscan;

/** One security problem found by the scanner. */
public record Finding(String id, String title, String severity, double cvss, String owasp,
                      String cwe, String type, String page, String evidence, String fix) {
}
