CREATE TYPE severity AS ENUM ('info','low','medium','high','critical');
CREATE TYPE event_source AS ENUM
  ('nginx','flask','auditd','sshd','postgres','docker','network','agent');

CREATE TABLE honeypots (
  id          smallint PRIMARY KEY,
  name        text UNIQUE NOT NULL,     -- 'hp1'
  hostname    text NOT NULL,            -- 'app-prod-01'
  role        text NOT NULL,            -- 'web' | 'app' | 'db'
  subnet      text NOT NULL,
  is_active   boolean NOT NULL DEFAULT true
);

CREATE TABLE agent_tokens (            -- solo metadatos, nunca el token
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  honeypot_id  smallint NOT NULL REFERENCES honeypots,
  kid          text UNIQUE NOT NULL,
  issued_at    timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz
);

CREATE TABLE ip_addresses (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ip            inet UNIQUE NOT NULL,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL,
  asn           integer, asn_org text, country char(2),   -- enriquecimiento
  is_allowlisted boolean NOT NULL DEFAULT false,          -- tus IPs de prueba
  label         text,
  banned_at     timestamptz                               -- ligado a fail2ban
);

CREATE TABLE sessions (
  id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  honeypot_id        smallint NOT NULL REFERENCES honeypots,
  kind               text NOT NULL,       -- 'http' | 'ssh' | 'sql'
  src_ip             inet NOT NULL,       -- tal como lo ve el honeypot
  attacker_ip_id     bigint REFERENCES ip_addresses,  -- IP real resuelta
  parent_session_id  bigint REFERENCES sessions,      -- HP1 -> HP2 -> HP3
  auth_user          text,
  auth_method        text,                -- 'password' | 'publickey'
  key_fingerprint    text,
  started_at         timestamptz NOT NULL,
  ended_at           timestamptz
);

CREATE TABLE detection_rules (
  id          integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  code        text UNIQUE NOT NULL,   -- 'READ_BASH_HISTORY'
  description text NOT NULL,
  severity    severity NOT NULL,
  stage       smallint,               -- etapa de tu cadena (1 a 6)
  notify      boolean NOT NULL DEFAULT false
);

CREATE TABLE events (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  honeypot_id   smallint NOT NULL REFERENCES honeypots,
  agent_boot_id uuid NOT NULL,
  agent_seq     bigint NOT NULL,
  occurred_at   timestamptz NOT NULL,     -- declarado por el agente
  received_at   timestamptz NOT NULL DEFAULT now(),
  source        event_source NOT NULL,
  event_type    text NOT NULL,            -- 'file.read', 'ssh.login', ...
  severity      severity NOT NULL,        -- asignada por el colector
  rule_id       integer REFERENCES detection_rules,
  session_id    bigint REFERENCES sessions,
  attacker_ip_id bigint REFERENCES ip_addresses,
  payload       jsonb NOT NULL,           -- el evento original completo
  UNIQUE (honeypot_id, agent_boot_id, agent_seq)
);

CREATE TABLE alerts (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id      bigint NOT NULL REFERENCES events,
  rule_id       integer NOT NULL REFERENCES detection_rules,
  created_at    timestamptz NOT NULL DEFAULT now(),
  notified_at   timestamptz,
  notify_status text,                 -- 'sent' | 'failed' | 'pending'
  acknowledged_at timestamptz
);

CREATE TABLE auth_attempts (
  event_id bigint PRIMARY KEY REFERENCES events,
  service text NOT NULL,             -- 'flask_login' | 'ssh' | 'postgres'
  username text, secret text,        -- contraseña probada
  key_fingerprint text, success boolean NOT NULL
);
CREATE TABLE commands (
  event_id bigint PRIMARY KEY REFERENCES events,
  command_line text NOT NULL, truncated boolean NOT NULL DEFAULT false,
  cwd text, uid integer, auid bigint, exit_code integer
);
CREATE TABLE file_accesses (
  event_id bigint PRIMARY KEY REFERENCES events,
  path text NOT NULL, operation text NOT NULL,   -- 'read' | 'write' | ...
  via text NOT NULL,                             -- 'flask' | 'shell'
  success boolean NOT NULL
);
CREATE TABLE http_requests (
  event_id bigint PRIMARY KEY REFERENCES events,
  method text, path text, query text, status smallint, bytes integer,
  user_agent text, referer text, body_excerpt text
);
CREATE TABLE sql_statements (
  event_id bigint PRIMARY KEY REFERENCES events,
  db_user text, database text, command_tag text, statement text
);

CREATE TABLE honeytokens (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind text NOT NULL,                -- 'aws_key' | 'email' | 'api_key'
  value_hash text NOT NULL,          -- no guardes el valor, solo su hash
  planted_in text NOT NULL,          -- 'hp3.tokens_api'
  planted_at timestamptz NOT NULL
);
CREATE TABLE honeytoken_hits (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  honeytoken_id bigint NOT NULL REFERENCES honeytokens,
  seen_at timestamptz NOT NULL, src_ip inet, source text, details jsonb
);

CREATE TABLE heartbeats (
  honeypot_id smallint NOT NULL REFERENCES honeypots,
  received_at timestamptz NOT NULL DEFAULT now(),
  agent_seq bigint NOT NULL,
  auditd_ok boolean NOT NULL, rules_immutable boolean NOT NULL,
  agent_version text
);
CREATE TABLE honeypot_status (          -- una fila por honeypot
  honeypot_id smallint PRIMARY KEY REFERENCES honeypots,
  last_heartbeat_at timestamptz, last_event_at timestamptz,
  state text NOT NULL                   -- 'online' | 'silent' | 'compromised'
);

CREATE TABLE dashboard_users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);
