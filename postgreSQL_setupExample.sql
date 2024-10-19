
sudo -u postgres psql 

CREATE DATABASE exampleDatabaseHere;

CREATE USER exampleUserHere WITH PASSWORD 'examplePasswordHere';

GRANT ALL PRIVILEGES ON DATABASE exampleDatabaseHere TO exampleUserHere;

\c exampleDatabaseHere

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_superuser BOOLEAN DEFAULT FALSE,
    reset_token VARCHAR(255),
    reset_token_expiry TIMESTAMP,
    google_id VARCHAR(255),
    google_email VARCHAR(100),
    google_display_name VARCHAR(100),
    stripe_user_id VARCHAR(255),
    token VARCHAR(50),
    set_theme BOOLEAN DEFAULT FALSE,
    dark_mode BOOLEAN DEFAULT FALSE
);



GRANT INSERT ON TABLE users TO exampleUserHere;

GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO exampleUserHere;

GRANT SELECT ON TABLE users TO exampleUserHere;

GRANT UPDATE ON TABLE users TO exampleUserHere;

GRANT DELETE ON TABLE users TO exampleUserHere;



CREATE TABLE chat (
    serial SERIAL PRIMARY KEY,
    user_id VARCHAR(50),
    tid VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    server_name VARCHAR(50),
    server_id VARCHAR(50),
    server_role VARCHAR(50),
    channel_name VARCHAR(50),
    channel_id VARCHAR(50),
    channel_invite VARCHAR(100),
    invite_expiration TIMESTAMP,
    chat_text TEXT,
    attachment_type VARCHAR(50),
    og_attachment_name VARCHAR(100),
    attachment_unique_id VARCHAR(50),
    attachment_path VARCHAR(100),
    attachment_size VARCHAR(50),
    inbound_friend_request VARCHAR(100),
    outbound_friend_request VARCHAR(100),
    blocked_users VARCHAR(100),
    user_name VARCHAR (50)   
    profile_picture VARCHAR(255),
    profile_headline TEXT,
    user_bio TEXT,
    active_server VARCHAR(255)
);


GRANT INSERT ON TABLE chat TO exampleUserHere;

GRANT USAGE, SELECT ON SEQUENCE chat_serial_seq TO exampleUserHere;

GRANT SELECT ON TABLE chat TO exampleUserHere;

GRANT UPDATE ON TABLE chat TO exampleUserHere;

GRANT DELETE ON TABLE chat TO exampleUserHere;

INSERT INTO chat (user_id, server_name, server_id, channel_name, channel_id)
VALUES (0, 'Sandbox', 'Cs7u1XshYuJDbVD80000', 'General', '0000Cs7u1XYuJDbVD8sh');