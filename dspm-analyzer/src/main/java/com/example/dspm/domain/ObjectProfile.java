package com.example.dspm.domain;

import jakarta.persistence.*;
import java.time.OffsetDateTime;

@Entity
@Table(name = "object_profile")
public class ObjectProfile {

    @Id
    @Column(length = 64)
    private String objectId;

    private Long bytes;
    private Long lineCount;
    private Double avgLineLen;
    private Long maxLineLen;
    private Double ratioDigit;
    private Double ratioAlpha;
    private Double ratioSymbol;
    private Boolean hasCsvHeader;
    private OffsetDateTime profiledAt;

    // ----- getters/setters -----
    public String getObjectId() { return objectId; }
    public void setObjectId(String objectId) { this.objectId = objectId; }

    public Long getBytes() { return bytes; }
    public void setBytes(Long bytes) { this.bytes = bytes; }

    public Long getLineCount() { return lineCount; }
    public void setLineCount(Long lineCount) { this.lineCount = lineCount; }

    public Double getAvgLineLen() { return avgLineLen; }
    public void setAvgLineLen(Double avgLineLen) { this.avgLineLen = avgLineLen; }

    public Long getMaxLineLen() { return maxLineLen; }
    public void setMaxLineLen(Long maxLineLen) { this.maxLineLen = maxLineLen; }

    public Double getRatioDigit() { return ratioDigit; }
    public void setRatioDigit(Double ratioDigit) { this.ratioDigit = ratioDigit; }

    public Double getRatioAlpha() { return ratioAlpha; }
    public void setRatioAlpha(Double ratioAlpha) { this.ratioAlpha = ratioAlpha; }

    public Double getRatioSymbol() { return ratioSymbol; }
    public void setRatioSymbol(Double ratioSymbol) { this.ratioSymbol = ratioSymbol; }

    public Boolean getHasCsvHeader() { return hasCsvHeader; }
    public void setHasCsvHeader(Boolean hasCsvHeader) { this.hasCsvHeader = hasCsvHeader; }

    public OffsetDateTime getProfiledAt() { return profiledAt; }
    public void setProfiledAt(OffsetDateTime profiledAt) { this.profiledAt = profiledAt; }
}
