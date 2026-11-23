CREATE ROLE ingest LOGIN PASSWORD '...'   -- mejor desde un gestor de secretos
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  CONNECTION LIMIT 20;

ALTER ROLE ingest SET statement_timeout = '5s';
ALTER ROLE ingest SET idle_in_transaction_session_timeout = '10s';

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ingest;

-- Inserción pura (las columnas identity no requieren permisos de secuencia)
GRANT INSERT ON
  events, auth_attempts, commands, file_accesses, http_requests,
  sql_statements, rejected_events, heartbeats, alerts, honeytoken_hits
TO ingest;

-- Si usas INSERT ... RETURNING id, necesitas leer solo esa columna
GRANT SELECT (id) ON events TO ingest;

-- Sesiones: insertar, localizar para correlacionar y completar campos concretos
GRANT INSERT ON sessions TO ingest;
GRANT SELECT (id, honeypot_id, boot_id, session_ref, key_fingerprint,
              started_at, ended_at, kind) ON sessions TO ingest;
GRANT UPDATE (ended_at, parent_session_id, attacker_ip_id) ON sessions TO ingest;

-- IPs: upsert de last_seen y enriquecimiento
GRANT INSERT ON ip_addresses TO ingest;
GRANT SELECT (id, ip, is_allowlisted) ON ip_addresses TO ingest;
GRANT UPDATE (last_seen, asn, asn_org, country) ON ip_addresses TO ingest;

-- Estado de los honeypots
GRANT INSERT ON honeypot_status TO ingest;
GRANT SELECT (honeypot_id) ON honeypot_status TO ingest;
GRANT UPDATE (last_heartbeat_at, last_event_at, state) ON honeypot_status TO ingest;

-- Solo lectura de configuración
GRANT SELECT ON honeypots, agent_tokens, detection_rules, honeytokens TO ingest;
