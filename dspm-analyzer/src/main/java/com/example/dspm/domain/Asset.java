package com.example.analyzer.asset;

import com.vladmihalcea.hibernate.type.json.JsonBinaryType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Type;

import java.time.OffsetDateTime;
import java.util.Map;

@Entity
@Table(name = "asset")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class Asset {

    @Id
    @Column(length = 512)
    private String id;               // 수집기가 주는 global key(arn 등)

    @Column(nullable = false, length = 64)
    private String service;          // "s3", "rds", ...

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

    @Type(JsonBinaryType.class)
    @Column(columnDefinition = "jsonb")
    private Map<String, String> tags;

    @Type(JsonBinaryType.class)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> metadata;

    @Column(nullable = false, columnDefinition = "timestamptz")
    private OffsetDateTime updatedAt;
}
