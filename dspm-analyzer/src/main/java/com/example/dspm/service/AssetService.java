package com.example.analyzer.asset;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AssetService {
    private final AssetRepository repo;

    public void upsertAll(List<AssetDTO> dtos) {
        var entities = dtos.stream().map(dto -> {
            var entity = repo.findById(dto.getId()).orElseGet(Asset::new);
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
        }).toList();
        repo.saveAll(entities);
    }
}
