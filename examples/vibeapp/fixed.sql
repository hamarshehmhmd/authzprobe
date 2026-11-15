-- The fixes authzprobe suggested, applied to schema.sql.
drop policy "Profiles are viewable by users" on public.profiles;
create policy "profiles: owner can select" on public.profiles for select to authenticated using ((select auth.uid()) = id);

drop policy "Read own messages" on public.messages;
create policy "messages: owner can select" on public.messages for select to authenticated
  using ((select auth.uid()) = user_id or (select auth.uid()) = recipient_id);

alter table public.orders enable row level security;
revoke select, insert, update, delete on public.orders from anon;
create policy "orders: owner can select" on public.orders for select to authenticated using ((select auth.uid()) = user_id);

drop policy "Authors edit posts" on public.posts;
create policy "posts: owner can update" on public.posts for update to authenticated
  using ((select auth.uid()) = author_id) with check ((select auth.uid()) = author_id);

revoke execute on function public.get_user_stats() from anon, public;
