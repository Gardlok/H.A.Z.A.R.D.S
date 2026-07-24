-- Surrelish owns dynamic HAZARDS metadata. Dotfiles and secrets do not belong
-- here. This schema is intentionally small enough to evolve before runtime
-- database wiring is added.

DEFINE TABLE IF NOT EXISTS host SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS name ON TABLE host TYPE string;
DEFINE FIELD IF NOT EXISTS kind ON TABLE host TYPE string;
DEFINE FIELD IF NOT EXISTS last_seen_at ON TABLE host TYPE option<datetime>;

DEFINE TABLE IF NOT EXISTS project SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS name ON TABLE project TYPE string;
DEFINE FIELD IF NOT EXISTS root ON TABLE project TYPE string;
DEFINE FIELD IF NOT EXISTS role ON TABLE project TYPE string;

DEFINE TABLE IF NOT EXISTS workspace SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS profile ON TABLE workspace TYPE string;
DEFINE FIELD IF NOT EXISTS layout ON TABLE workspace TYPE string;
DEFINE FIELD IF NOT EXISTS opened_at ON TABLE workspace TYPE datetime;
DEFINE FIELD IF NOT EXISTS closed_at ON TABLE workspace TYPE option<datetime>;

DEFINE TABLE IF NOT EXISTS recipe_run SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS recipe ON TABLE recipe_run TYPE string;
DEFINE FIELD IF NOT EXISTS source_hash ON TABLE recipe_run TYPE string;
DEFINE FIELD IF NOT EXISTS started_at ON TABLE recipe_run TYPE datetime;
DEFINE FIELD IF NOT EXISTS finished_at ON TABLE recipe_run TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS outcome ON TABLE recipe_run TYPE string;
