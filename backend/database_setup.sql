CREATE DATABASE sih26145 CHARACTER SET utf8mb4;
-- Replace CHANGEME_PASSWORD with your own local password (matches DB_PASSWORD in config.py / .env)
CREATE USER 'sih_app'@'localhost' IDENTIFIED BY 'CHANGEME_PASSWORD';
GRANT ALL PRIVILEGES ON sih26145.* TO 'sih_app'@'localhost';
FLUSH PRIVILEGES;

use sih26145;

SELECT DATABASE();
SELECT COUNT(*) FROM traffic;
