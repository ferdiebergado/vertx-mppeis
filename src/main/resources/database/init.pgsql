-- DROP TABLE classes;
-- DROP TABLE teachers;
-- DROP TABLE positions;
-- DROP TABLE schools;
-- DROP TABLE districts;
-- DROP TABLE divisions;
-- DROP TABLE regions;
-- DROP TABLE users;

CREATE TABLE IF NOT EXISTS regions (
    id SERIAL2 PRIMARY KEY NOT NULL,
    name VARCHAR(50) NOT NULL,
    sequence SMALLINT NOT NULL,
    area CHAR(1) DEFAULT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS divisions (
    id SERIAL2 PRIMARY KEY NOT NULL,
    name VARCHAR(50) NOT NULL,
    region_id SMALLINT NOT NULL REFERENCES regions(id),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS districts (
    id SERIAL2 PRIMARY KEY NOT NULL,
    name VARCHAR(50) NOT NULL,
    division_id SMALLINT NOT NULL REFERENCES divisions(id),
    region_id SMALLINT NOT NULL REFERENCES regions(id),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    created_by INT DEFAULT NULL,
    updated_by INT DEFAULT NULL,
    deleted_by INT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS schools (
    id SERIAL PRIMARY KEY,
    school_id INT NOT NULL UNIQUE,
    name VARCHAR(150) NOT NULL,
    year_established SMALLINT DEFAULT NULL,
    school_type CHARACTER(1) NOT NULL,
    school_location CHARACTER(1) NOT NULL,
    region_id SMALLINT NOT NULL REFERENCES regions(id),
    division_id SMALLINT DEFAULT NULL REFERENCES divisions(id),
    district_id SMALLINT DEFAULT NULL REFERENCES districts(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    created_by INT DEFAULT NULL,
    updated_by INT DEFAULT NULL,
    deleted_by INT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS positions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) DEFAULT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    created_by INT DEFAULT NULL,
    updated_by INT DEFAULT NULL,
    deleted_by INT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS teachers (
    id SERIAL PRIMARY KEY,
    last_name VARCHAR(150) NOT NULL,
    first_name VARCHAR(150) NOT NULL,
    mi CHAR(3) DEFAULT NULL,
    sex CHAR(1) NOT NULL,
    position_id INT NOT NULL REFERENCES positions(id),
    school_id INT NOT NULL REFERENCES schools(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    created_by INT DEFAULT NULL,
    updated_by INT DEFAULT NULL,
    deleted_by INT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS classes (
    id SERIAL PRIMARY KEY,
    school_year SMALLINT NOT NULL,
    school_id INT NOT NULL REFERENCES schools(id),
    teacher_id INT NOT NULL REFERENCES teachers(id),
    grade SMALLINT NOT NULL,
    section VARCHAR(30) DEFAULT NULL,
    males SMALLINT NOT NULL,
    females SMALLINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    created_by INT DEFAULT NULL,
    updated_by INT DEFAULT NULL,
    deleted_by INT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    verification_token VARCHAR(255) DEFAULT NULL UNIQUE,
    is_active BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMPTZ DEFAULT NULL,
    role SMALLINT DEFAULT 3,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    created_by INT DEFAULT NULL,
    updated_by INT DEFAULT NULL,
    deleted_by INT DEFAULT NULL
);

INSERT INTO regions (name, sequence, area) VALUES ('I', 1, 'L');
INSERT INTO divisions (name, region_id) VALUES ('Ilocos Norte', 1);
INSERT INTO districts (name, division_id, region_id) VALUES ('Bacarra', 1, 1);
INSERT INTO positions (name) VALUES ('Teacher I');
