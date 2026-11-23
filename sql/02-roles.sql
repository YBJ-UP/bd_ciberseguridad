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

-- Vigilante de heartbeats + notificaciones a Telegram
CREATE ROLE notifier LOGIN ...;
GRANT SELECT ON honeypot_status, alerts, detection_rules TO notifier;
GRANT SELECT (id, event_type, occurred_at, honeypot_id) ON events TO notifier;
GRANT UPDATE (notified_at, notify_status) ON alerts TO notifier;
GRANT UPDATE (state) ON honeypot_status TO notifier;

-- Consultas del front: todo menos el secreto
CREATE ROLE query LOGIN ...;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO query;
REVOKE SELECT ON auth_attempts FROM query;
GRANT SELECT (event_id, service, username, key_fingerprint, success)
  ON auth_attempts TO query;
GRANT UPDATE (acknowledged_at) ON alerts TO query;

-- Analítica de python: solo lectura, idealmente sobre vistas sin `secret`
CREATE ROLE analytics LOGIN ...;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO analytics;
REVOKE SELECT ON auth_attempts FROM analytics;
