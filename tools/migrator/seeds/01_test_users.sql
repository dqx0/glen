-- Seed: test_users
-- Created: 2025-07-06 21:52:00

-- Test users for development and testing
-- All users have password: password123
INSERT INTO users (id, username, email, password_hash, email_verified, status) VALUES 
  ('123e4567-e89b-12d3-a456-426614174000', 'testuser', 'test@example.com', '$2a$10$AW3t5bO9nrNwFZlAgVmMUe2Md0qtYIirrxM4KuvzHSntMzCfZPYUK', true, 'active'),
  ('223e4567-e89b-12d3-a456-426614174001', 'alice', 'alice@example.com', '$2a$10$AW3t5bO9nrNwFZlAgVmMUe2Md0qtYIirrxM4KuvzHSntMzCfZPYUK', true, 'active'),
  ('323e4567-e89b-12d3-a456-426614174002', 'bob', 'bob@example.com', '$2a$10$AW3t5bO9nrNwFZlAgVmMUe2Md0qtYIirrxM4KuvzHSntMzCfZPYUK', false, 'active'),
  ('423e4567-e89b-12d3-a456-426614174003', 'webauthn_user', 'webauthn@example.com', NULL, true, 'active'),
  ('523e4567-e89b-12d3-a456-426614174004', 'dqx0', 'dqx0@example.com', NULL, true, 'active');