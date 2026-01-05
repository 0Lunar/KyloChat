CREATE DATABASE IF NOT EXISTS KyloChatDB;

USE KyloChatDB;

CREATE TABLE users(
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(60),
    email VARCHAR(120),
    banned BOOLEAN DEFAULT false,
    admin BOOLEAN DEFAULT false
);


CREATE TABLE credentials(
    CredID INT AUTO_INCREMENT PRIMARY KEY,
    user INT,
    password VARCHAR(60),    -- - Bcrypt

    FOREIGN KEY (user) REFERENCES users(UserID)
);


CREATE TABLE tokens(
    TokenID INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(36) NOT NULL UNIQUE,
    user INT,
    expire DATETIME,
    revoked BOOL,

    FOREIGN KEY (user) REFERENCES users(UserID)
);

-- - SETUP FOR ADMIN USER (PASSWORD: 'admin'; UPDATE ON RELEASE)

INSERT INTO users(username, email, admin) VALUES("admin", "<admin_mail>", true);
INSERT INTO credentials(user, password) VALUES((SELECT users.UserID FROM users WHERE users.username='admin'), "$2b$12$TRG9kqWU2C9Unq5QMo5xUeJYaydMnna9ktI1NZfbgnVquOa4r1X7i");

-- - SETUP FOR TEST USER (PASSWORD: 'test')

INSERT INTO users(username, email, admin) VALUES("test", "test@test.test", false);
INSERT INTO credentials(user, password) VALUES((SELECT users.UserID FROM users WHERE users.username='test'), "$2b$12$eZHlQMeHQ0uN1Sdat8ktWO2mkDlgqihUlGzHlNTcKCV7FHy2YqZ5m");