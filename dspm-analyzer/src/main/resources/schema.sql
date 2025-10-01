create table if not exists asset (
  id           varchar(512) primary key,
  service      varchar(64)  not null,
  kind         varchar(32)  not null,
  region       varchar(64),
  name         varchar(256),
  uri          varchar(1024),
  size_bytes   bigint,
  encrypted    boolean,
  kms_key_id   varchar(256),
  tags         jsonb,
  metadata     jsonb,
  updated_at   timestamptz  not null default now()
);

create index if not exists idx_asset_service on asset(service);
create index if not exists idx_asset_kind on asset(kind);
create index if not exists idx_asset_region on asset(region);
