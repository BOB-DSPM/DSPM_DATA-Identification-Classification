package com.example.dspm.web.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.Map;

public record MetaIn(
    @NotBlank String sourceId,
    @NotBlank String objectType,
    @NotBlank String locator,
    String parentLocator,
    Long bytes,
    Map<String, Object> extra
) {}
