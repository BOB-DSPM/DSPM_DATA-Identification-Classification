package com.example.dspm.domain;

public enum AssetKind {
    ObjectStore, FileStore, BlockStore,
    Database, DataWarehouse, NoSQL, GraphDB, TimeSeries, Ledger,
    LogStore, Stream, Queue, Topic, EventBus, Search,
    MLArtifact, ETL, Backup, Secrets, Params, Registry, Docs, Other
}
