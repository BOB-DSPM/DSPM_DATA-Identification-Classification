package com.example.dspm.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.Map;

@Entity
@Table(
    name = "data_object",
    uniqueConstraints = { @UniqueConstraint(name = "uq_locator", columnNames = "locator") }
)
public class DataObject {

    @Id
    @Column(length = 64)
    private String id;

    @Column(nullable = false)
    private String sourceId;

    @Column(nullable = false)
    private String objectType;

    @Column(nullable = false)
    private String locator;

    private String parentLocator;

    private Long bytes;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> extra;

    private OffsetDateTime firstSeen;
    private OffsetDateTime lastScanned;
    private OffsetDateTime lastModified;

    private String etag;
    private String checksum;
    private String version;

    // ----- getters/setters -----
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getSourceId() { return sourceId; }
    public void setSourceId(String sourceId) { this.sourceId = sourceId; }

    public String getObjectType() { return objectType; }
    public void setObjectType(String objectType) { this.objectType = objectType; }

    public String getLocator() { return locator; }
    public void setLocator(String locator) { this.locator = locator; }

    public String getParentLocator() { return parentLocator; }
    public void setParentLocator(String parentLocator) { this.parentLocator = parentLocator; }

    public Long getBytes() { return bytes; }
    public void setBytes(Long bytes) { this.bytes = bytes; }

    public Map<String, Object> getExtra() { return extra; }
    public void setExtra(Map<String, Object> extra) { this.extra = extra; }

    public OffsetDateTime getFirstSeen() { return firstSeen; }
    public void setFirstSeen(OffsetDateTime firstSeen) { this.firstSeen = firstSeen; }

    public OffsetDateTime getLastScanned() { return lastScanned; }
    public void setLastScanned(OffsetDateTime lastScanned) { this.lastScanned = lastScanned; }

    public OffsetDateTime getLastModified() { return lastModified; }
    public void setLastModified(OffsetDateTime lastModified) { this.lastModified = lastModified; }

    public String getEtag() { return etag; }
    public void setEtag(String etag) { this.etag = etag; }

    public String getChecksum() { return checksum; }
    public void setChecksum(String checksum) { this.checksum = checksum; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
}
