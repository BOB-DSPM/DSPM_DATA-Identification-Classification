package com.example.dspm.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record BulkIn(
    @NotBlank String sourceId,
    @NotNull List<AssetIn> items
) {}
