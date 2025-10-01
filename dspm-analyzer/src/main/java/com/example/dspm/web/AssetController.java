package com.example.dspm.web;

import com.example.dspm.service.AssetService;
import com.example.dspm.web.dto.AssetDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/assets")
public class AssetController {

    private final AssetService service;

    @PostMapping("/bulk")
    public ResponseEntity<Void> bulk(@RequestBody List<AssetDTO> assets) {
        service.upsertBulk(assets);   
        return ResponseEntity.ok().build();
    }
}