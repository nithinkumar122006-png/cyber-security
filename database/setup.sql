-- Cybersecurity Management System database
-- Import this file in phpMyAdmin using the Import tab.
-- Creates the database and tables used by the application.

CREATE DATABASE IF NOT EXISTS cybersecurity_management
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cybersecurity_management;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    username VARCHAR(60) NOT NULL UNIQUE,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    target VARCHAR(500) DEFAULT NULL,
    result_status VARCHAR(40) NOT NULL,
    result_summary TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scan_history_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS awareness_questions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    question TEXT NOT NULL,
    option_a VARCHAR(255) NOT NULL,
    option_b VARCHAR(255) NOT NULL,
    option_c VARCHAR(255) NOT NULL,
    option_d VARCHAR(255) NOT NULL,
    correct_option ENUM('A', 'B', 'C', 'D') NOT NULL,
    explanation TEXT
);

CREATE TABLE IF NOT EXISTS security_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    report_title VARCHAR(180) NOT NULL,
    report_body MEDIUMTEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_reports_user
      FOREIGN KEY (user_id) REFERENCES users(id)
      ON DELETE CASCADE
);

-- Add starter awareness questions only when the table is empty.
INSERT INTO awareness_questions
(question, option_a, option_b, option_c, option_d, correct_option, explanation)
SELECT * FROM (
    SELECT
      'Which action is safest when you receive an unexpected email attachment?',
      'Open it immediately',
      'Verify the sender and scan the file before opening',
      'Forward it to everyone',
      'Disable antivirus first',
      'B',
      'Unexpected attachments can contain malware. Verify the sender and use approved scanning tools.'
) AS starter
WHERE NOT EXISTS (SELECT 1 FROM awareness_questions LIMIT 1);

INSERT INTO awareness_questions
(question, option_a, option_b, option_c, option_d, correct_option, explanation)
SELECT * FROM (
    SELECT
      'What should you do if a website asks for your password through an unexpected link?',
      'Enter the password quickly',
      'Reuse a simple password',
      'Open the official website directly and verify the request',
      'Share the link with colleagues',
      'C',
      'Unexpected login links may be phishing. Navigate to the official site yourself.'
) AS starter
WHERE NOT EXISTS (
    SELECT 1 FROM awareness_questions
    WHERE question = 'What should you do if a website asks for your password through an unexpected link?'
);
