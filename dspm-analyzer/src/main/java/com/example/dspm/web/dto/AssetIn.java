package com.example.dspm.web.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.Map;

public record AssetIn(
    @NotBlank String kind,
    @NotBlank String locator,
    @NotBlank String name,
    @NotBlank String region,
    Long bytes,
    Map<String, Object> meta
) {}
