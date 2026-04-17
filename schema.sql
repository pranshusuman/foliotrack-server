-- FolioTrack Database Schema
-- Run this in: supabase.com → your project → SQL Editor → New query → Run

-- Users table
create table if not exists users (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  email text unique not null,
  password text not null,
  notify_email boolean default true,
  created_at timestamptz default now()
);

-- Holdings table (current positions)
create table if not exists holdings (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references users(id) on delete cascade,
  ticker text not null,
  exchange text not null default 'NSE',
  qty numeric not null,
  avg_cost numeric not null,
  buy_date date,
  created_at timestamptz default now(),
  unique(user_id, ticker, exchange)
);

-- Transactions table (full history)
create table if not exists transactions (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references users(id) on delete cascade,
  ticker text not null,
  exchange text not null default 'NSE',
  qty numeric not null,
  price numeric not null,
  date date not null,
  type text not null check (type in ('buy', 'sell')),
  created_at timestamptz default now()
);

-- Row Level Security (each user only sees their own data)
alter table users enable row level security;
alter table holdings enable row level security;
alter table transactions enable row level security;

create policy "users_own" on users for all using (auth.uid()::text = id::text);
create policy "holdings_own" on holdings for all using (auth.uid()::text = user_id::text);
create policy "transactions_own" on transactions for all using (auth.uid()::text = user_id::text);

-- Indexes for performance
create index if not exists idx_holdings_user on holdings(user_id);
create index if not exists idx_transactions_user on transactions(user_id);
create index if not exists idx_transactions_ticker on transactions(ticker);
