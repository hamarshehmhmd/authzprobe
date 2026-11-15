-- "Vibe-coded" community app schema with the mistakes that keep leaking Lovable/Bolt apps.
-- Each table is a different case; see the comments.

-- profiles: RLS on, but "any logged-in user can read every profile" (emails, phone numbers).
create table public.profiles (
  id uuid primary key,
  username text not null,
  email text,
  phone text,
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
create policy "Profiles are viewable by users" on public.profiles for select to authenticated using (true);
create policy "Users insert own profile" on public.profiles for insert to authenticated with check (auth.uid() = id);
create policy "Users update own profile" on public.profiles for update to authenticated using (auth.uid() = id);

-- messages: an AI-written guard that's inverted. Logged-in users only see their own,
-- but anonymous requests (auth.uid() is null) get everything.
create table public.messages (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  recipient_id uuid,
  content text not null,
  created_at timestamptz not null default now()
);
alter table public.messages enable row level security;
create policy "Read own messages" on public.messages for select
  using (auth.uid() is null or auth.uid() = user_id or auth.uid() = recipient_id);
create policy "Send messages" on public.messages for insert to authenticated with check (auth.uid() = user_id);

-- orders: RLS never enabled. With Supabase's default grants, the anon key can read, edit and delete it.
create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount numeric not null,
  status text not null default 'paid',
  shipping_address text
);

-- notes: done right. Owner-only for every command.
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid(),
  title text not null
);
alter table public.notes enable row level security;
create policy "notes select" on public.notes for select to authenticated using ((select auth.uid()) = user_id);
create policy "notes insert" on public.notes for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "notes update" on public.notes for update to authenticated using ((select auth.uid()) = user_id);
create policy "notes delete" on public.notes for delete to authenticated using ((select auth.uid()) = user_id);

-- posts: public on purpose (read), but the update policy was "fixed" with using (true).
create table public.posts (
  id bigint generated always as identity primary key,
  author_id uuid not null,
  title text not null
);
alter table public.posts enable row level security;
create policy "Posts are public" on public.posts for select using (true);
create policy "Authors create posts" on public.posts for insert to authenticated with check (auth.uid() = author_id);
create policy "Authors edit posts" on public.posts for update to authenticated using (true);
create policy "Authors delete posts" on public.posts for delete to authenticated using (auth.uid() = author_id);

create function public.get_user_stats() returns json language sql security definer as $$
  select json_build_object('users', (select count(*) from public.profiles))
$$;

-- Some existing data from two real users.
insert into public.profiles (id, username, email, phone) values
  ('11111111-1111-4111-8111-111111111111', 'alice', 'alice@example.com', '+351 912 000 001'),
  ('22222222-2222-4222-8222-222222222222', 'bob', 'bob@example.com', '+351 912 000 002');
insert into public.messages (user_id, recipient_id, content) values
  ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222', 'my new passport number is ...'),
  ('22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111', 'see you at 8');
insert into public.orders (user_id, amount, shipping_address) values
  ('11111111-1111-4111-8111-111111111111', 49.90, 'Rua Augusta 1, Lisboa'),
  ('22222222-2222-4222-8222-222222222222', 12.00, 'Main St 5, Porto');
insert into public.notes (user_id, title) values ('11111111-1111-4111-8111-111111111111', 'private note');
insert into public.posts (author_id, title) values ('11111111-1111-4111-8111-111111111111', 'Hello world');
