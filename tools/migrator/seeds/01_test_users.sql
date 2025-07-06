-- Seed: test_users
-- Created: 2025-07-06 21:52:00

-- Test users for development and testing
INSERT INTO users (id, username, email, password_hash, email_verified, is_active) VALUES 
  ('123e4567-e89b-12d3-a456-426614174000', 'testuser', 'test@example.com', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LefrV7uFd0jvdwuW6', true, true),
  ('223e4567-e89b-12d3-a456-426614174001', 'alice', 'alice@example.com', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LefrV7uFd0jvdwuW6', true, true),
  ('323e4567-e89b-12d3-a456-426614174002', 'bob', 'bob@example.com', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LefrV7uFd0jvdwuW6', false, true),
  ('423e4567-e89b-12d3-a456-426614174003', 'webauthn_user', 'webauthn@example.com', NULL, true, true);