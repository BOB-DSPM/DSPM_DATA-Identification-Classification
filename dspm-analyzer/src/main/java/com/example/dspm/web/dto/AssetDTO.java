package com.example.dspm.web.dto;

import com.example.dspm.domain.AssetKind;
import lombok.Data;
import java.util.Map;

@Data
public class AssetDTO {
    private String id;
    private String service;
    private AssetKind kind;
    private String region;
    private String name;
    private String uri;
    private Long sizeBytes;
    private Boolean encrypted;
    private String kmsKeyId;
    private Map<String,String> tags;
    private Map<String,Object> metadata;
}
