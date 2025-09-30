package com.example.dspm.domain;

import jakarta.persistence.*;
import java.time.OffsetDateTime;

@Entity
@Table(name = "pseudonymization_guard")
public class PseudonymizationGuard {

    @Id
    @Column(length = 64)
    private String objectId;

    @Column(nullable = false)
    private Boolean isPseudonymized;

    private String mappingLocator;
    private Boolean separated;
    private String separationReason;
    private OffsetDateTime checkedAt;

    // ----- getters/setters -----
    public String getObjectId() { return objectId; }
    public void setObjectId(String objectId) { this.objectId = objectId; }

    public Boolean getIsPseudonymized() { return isPseudonymized; }
    public void setIsPseudonymized(Boolean isPseudonymized) { this.isPseudonymized = isPseudonymized; }

    public String getMappingLocator() { return mappingLocator; }
    public void setMappingLocator(String mappingLocator) { this.mappingLocator = mappingLocator; }

    public Boolean getSeparated() { return separated; }
    public void setSeparated(Boolean separated) { this.separated = separated; }

    public String getSeparationReason() { return separationReason; }
    public void setSeparationReason(String separationReason) { this.separationReason = separationReason; }

    public OffsetDateTime getCheckedAt() { return checkedAt; }
    public void setCheckedAt(OffsetDateTime checkedAt) { this.checkedAt = checkedAt; }
}
