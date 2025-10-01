package com.example.dspm.service;

import com.example.dspm.domain.Asset;
import com.example.dspm.repo.AssetRepository;
import com.example.dspm.web.dto.AssetDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AssetService {

    private final AssetRepository repo;

    public void upsertBulk(List<AssetDTO> dtos) {
        var entities = dtos.stream().map(dto -> {
            var entity = repo.findById(dto.getId()).orElseGet(Asset::new);  // ✅ getId()

            entity.setId(dto.getId());
            entity.setService(dto.getService());
            entity.setKind(dto.getKind());
            entity.setRegion(dto.getRegion());
            entity.setName(dto.getName());
            entity.setUri(dto.getUri());
            entity.setSizeBytes(dto.getSizeBytes());
            entity.setEncrypted(dto.getEncrypted());
            entity.setKmsKeyId(dto.getKmsKeyId());
            entity.setTags(dto.getTags());
            entity.setMetadata(dto.getMetadata());
            entity.setUpdatedAt(OffsetDateTime.now());

            return entity;
        }).collect(Collectors.toList());

        repo.saveAll(entities);
    }
}