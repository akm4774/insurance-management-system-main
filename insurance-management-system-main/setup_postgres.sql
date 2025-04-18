-- 1. Create an ENUM type for claim status (only once)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type WHERE typname = 'claim_status'
  ) THEN
    CREATE TYPE claim_status AS ENUM ('Pending', 'Approved', 'Rejected');
  END IF;
END
$$;

-- 2. Users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL
);

-- 3. Policies table
CREATE TABLE IF NOT EXISTS policies (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL
    REFERENCES users(id) ON DELETE CASCADE,
  policy_name VARCHAR(255) NOT NULL,
  policy_type VARCHAR(255) NOT NULL,
  premium_amount NUMERIC(10,2) NOT NULL
);

-- 4. Claims table
CREATE TABLE IF NOT EXISTS claims (
  id SERIAL PRIMARY KEY,
  policy_id INT NOT NULL
    REFERENCES policies(id) ON DELETE CASCADE,
  claim_date DATE NOT NULL,
  claim_amount NUMERIC(10,2) NOT NULL,
  status claim_status NOT NULL DEFAULT 'Pending'
);

-- 5. Sample data (idempotent)
INSERT INTO users (name, email, password)
VALUES
  ('John Doe',  'john@example.com', 'password123'),
  ('Jane Smith','jane@example.com', 'securepass')
ON CONFLICT (email) DO NOTHING;

INSERT INTO policies (user_id, policy_name, policy_type, premium_amount)
VALUES
  ((SELECT id FROM users WHERE email='john@example.com'),
   'Health Insurance Plan A','Health',5000.00),
  ((SELECT id FROM users WHERE email='john@example.com'),
   'Car Insurance Basic','Vehicle',3000.00),
  ((SELECT id FROM users WHERE email='jane@example.com'),
   'Life Insurance Gold','Life',7000.00)
ON CONFLICT DO NOTHING;

INSERT INTO claims (policy_id, claim_date, claim_amount, status)
VALUES
  ((SELECT id FROM policies WHERE policy_name='Health Insurance Plan A'),
   '2024-03-30',2000.00,'Approved'),
  ((SELECT id FROM policies WHERE policy_name='Car Insurance Basic'),
   '2024-03-28',1500.00,'Pending')
ON CONFLICT DO NOTHING;

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT FALSE;
