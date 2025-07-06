-- Seed: test_social_accounts
-- Created: 2025-07-06 21:52:30

-- Test social accounts
INSERT INTO social_accounts (id, user_id, provider, provider_user_id, provider_username, provider_email) VALUES 
  ('523e4567-e89b-12d3-a456-426614174004', '123e4567-e89b-12d3-a456-426614174000', 'google', '12345678901234567890', 'testuser', 'test@gmail.com'),
  ('623e4567-e89b-12d3-a456-426614174005', '223e4567-e89b-12d3-a456-426614174001', 'github', 'alice123', 'alice', 'alice@users.noreply.github.com'),
  ('723e4567-e89b-12d3-a456-426614174006', '323e4567-e89b-12d3-a456-426614174002', 'discord', '987654321098765432', 'bob#1234', 'bob@discord.local');