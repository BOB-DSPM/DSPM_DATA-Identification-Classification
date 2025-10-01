package com.example.dspm.domain;

import com.example.dspm.domain.AssetKind;
import io.hypersistence.utils.hibernate.type.json.JsonType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Type;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;

@Entity
@Table(name = "asset")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class Asset {

    @Id
    @Column(length = 512)
    private String id;

    @Column(nullable = false, length = 64)
    private String service;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AssetKind kind;

    @Column(length = 64)
    private String region;

    @Column(length = 256)
    private String name;

    @Column(length = 1024)
    private String uri;

    private Long sizeBytes;

    private Boolean encrypted;

    @Column(length = 256)
    private String kmsKeyId;

    // Hibernate 6 + hibernate-types-60
    @Type(JsonType.class)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, String> tags = new HashMap<>();

    @Type(JsonType.class)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    @Column(nullable = false, columnDefinition = "timestamptz")
    private OffsetDateTime updatedAt;

    @PrePersist
    @PreUpdate
    public void touchUpdatedAt() {
        this.updatedAt = OffsetDateTime.now();
    }
}
