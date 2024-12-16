CREATE DATABASE test_db;

\c test_db;

CREATE TABLE users (
	id SERIAL PRIMARY KEY,
	username VARCHAR(50),
	password VARCHAR(50)
);

INSERT INTO users (username, password) VALUES
('admin', 'password123'),
('user1', 'mypass'),
('user2', 'letme');
