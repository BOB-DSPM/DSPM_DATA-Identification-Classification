package com.example.analyzer.asset;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/assets")
@RequiredArgsConstructor
public class AssetController {
    private final AssetService service;

    @PostMapping("/bulk")
    public ResponseEntity<Void> bulk(@RequestBody List<AssetDTO> assets) {
        service.upsertAll(assets);
        return ResponseEntity.ok().build();
    }
}
