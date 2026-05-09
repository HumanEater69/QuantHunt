create extension if not exists pgcrypto;

create table if not exists public.scan_jobs (
  id uuid primary key default gen_random_uuid(),
  target_domain text not null,
  status text not null default 'pending'
    check (status in ('pending', 'running', 'completed', 'failed')),
  results jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists scan_jobs_touch_updated_at on public.scan_jobs;
create trigger scan_jobs_touch_updated_at
before update on public.scan_jobs
for each row execute function public.touch_updated_at();

create or replace function public.claim_pending_scan()
returns public.scan_jobs
language plpgsql
security definer
set search_path = public
as $$
declare
  v_scan public.scan_jobs;
begin
  select *
  into v_scan
  from public.scan_jobs
  where status = 'pending'
  order by created_at asc
  for update skip locked
  limit 1;

  if not found then
    return null;
  end if;

  update public.scan_jobs
  set status = 'running'
  where id = v_scan.id
  returning * into v_scan;

  return v_scan;
end;
$$;

alter publication supabase_realtime add table public.scan_jobs;
