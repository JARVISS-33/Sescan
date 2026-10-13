package com.secscan;

import jakarta.persistence.*;
import java.time.Instant;

/** One row in the "scans" table of the database. */
@Entity
@Table(name = "scans")
public class ScanEntity {
    @Id
    public String id;
    @Column(columnDefinition = "text")
    public String url;
    public String status;          // RUNNING, DONE, FAILED
    public Integer score;
    public String grade;
    public Integer pagesCount;
    @Column(columnDefinition = "text")
    public String resultJson;      // {"pages":[...],"findings":[...]}
    @Column(columnDefinition = "text")
    public String logText;
    public Instant createdAt;
}
