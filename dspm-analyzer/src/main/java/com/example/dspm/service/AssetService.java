package com.example.dspm.service;

import com.example.dspm.domain.Asset;
import com.example.dspm.repo.AssetRepository;
import com.example.dspm.web.dto.AssetDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AssetService {

    private final AssetRepository repo;

    @Transactional
    public void upsertBulk(List<AssetDTO> dtos) {
        List<Asset> entities = new ArrayList<>(dtos.size()); 

        for (var dto : dtos) {
            // DTO가 record라면 접근자는 id(), service() ...
            var entity = repo.findById(dto.id()).orElseGet(Asset::new);
            entity.setId(dto.id());
            entity.setService(dto.service());
            entity.setKind(dto.kind());
            entity.setRegion(dto.region());
            entity.setName(dto.name());
            entity.setUri(dto.uri());
            entity.setSizeBytes(dto.sizeBytes());
            entity.setEncrypted(dto.encrypted());
            entity.setKmsKeyId(dto.kmsKeyId());
            entity.setTags(dto.tags());
            entity.setMetadata(dto.metadata());
            entities.add(entity);
        }

        repo.saveAll(entities); // Iterable<Asset>
    }
}
