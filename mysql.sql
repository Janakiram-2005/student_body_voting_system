-- 1. Create and use the database
CREATE DATABASE IF NOT EXISTS sbvs;
USE sbvs;

-- 2. Admin table
DROP TABLE IF EXISTS admin;
CREATE TABLE admin (
    adminid INT AUTO_INCREMENT PRIMARY KEY,
    adminname VARCHAR(100),
    adminemail VARCHAR(100) UNIQUE,
    adminpassword VARCHAR(255),
    adminphno VARCHAR(15)
);

-- Optional: Insert default admin (password is plain here; you can bcrypt hash it later)
INSERT INTO admin (adminname, adminemail, adminpassword, adminphno)
VALUES ('SBVS Admin', 'ad', 'admin123', '9999999999');

-- 3. Candidates table
DROP TABLE IF EXISTS candidates;
CREATE TABLE candidates (
    canid INT AUTO_INCREMENT PRIMARY KEY,
    canname VARCHAR(100),
    canemail VARCHAR(100) UNIQUE,
    canpassword VARCHAR(255),
    canphno VARCHAR(15),
    candesc TEXT
);

-- 4. Voters table
DROP TABLE IF EXISTS voters;
CREATE TABLE voters (
    id INT AUTO_INCREMENT PRIMARY KEY,
    voterreg VARCHAR(100) UNIQUE,
    has_voted BOOLEAN DEFAULT FALSE
);

-- 5. Settings table (controls voting flow)
DROP TABLE IF EXISTS settings;
CREATE TABLE settings (
    id INT PRIMARY KEY,
    voting_status ENUM('not_started', 'started', 'ended', 'final_released') DEFAULT 'not_started',
    final_result_released BOOLEAN DEFAULT FALSE,
    results_approved BOOLEAN DEFAULT FALSE
);

-- Ensure default settings row
INSERT INTO settings (id, voting_status, final_result_released, results_approved)
VALUES (1, 'not_started', FALSE, FALSE)
ON DUPLICATE KEY UPDATE voting_status = 'not_started';

-- 6. Votes table
DROP TABLE IF EXISTS votes;
CREATE TABLE votes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    voterreg VARCHAR(100),
    candidate_id INT,
    FOREIGN KEY (voterreg) REFERENCES voters(voterreg) ON DELETE CASCADE,
    FOREIGN KEY (candidate_id) REFERENCES candidates(canid) ON DELETE CASCADE
);

-- 7. Vote history table
DROP TABLE IF EXISTS vote_history;
CREATE TABLE vote_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    voterreg VARCHAR(100),
    candidate_id INT,
    voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 8. Complaints table
DROP TABLE IF EXISTS complaints;
CREATE TABLE complaints (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Optional: View data
SELECT * FROM admin;
SELECT * FROM candidates;
SELECT * FROM voters;
SELECT * FROM votes;
SELECT * FROM settings;
select * FROM vote_history;
select * from complaints;

drop table admin;
drop table candidates;
drop table voters;
drop table votes;
drop table settings;

DROP DATABASE IF EXISTS sbvs;

