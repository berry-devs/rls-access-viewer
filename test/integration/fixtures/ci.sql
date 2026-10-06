-- Fixture for the CI integration workflow, loaded into the public schema of a freshly started local Supabase stack.
-- It gives every integration test something to check: tables, views, RLS (FOR ALL, PERMISSIVE and RESTRICTIVE),
-- foreign key actions, GRANT differences, SECURITY DEFINER functions, a PL/pgSQL trigger with guards, and Storage.
-- Storage tables are created by storage-api; this file only adds rows and policies to them.

BEGIN;

CREATE TABLE public.organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL
);

CREATE TABLE public.members (
  organization_id uuid NOT NULL REFERENCES public.organizations (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'member',
  PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE public.documents (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES public.organizations (id) ON DELETE CASCADE,
  owner_id uuid DEFAULT auth.uid() REFERENCES auth.users (id) ON DELETE SET NULL,
  title text NOT NULL,
  status text NOT NULL DEFAULT 'draft',
  archived boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.comments (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  document_id bigint NOT NULL REFERENCES public.documents (id) ON DELETE CASCADE,
  author_id uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  body text NOT NULL
);

CREATE FUNCTION public.is_member(org uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.members m WHERE m.organization_id = org AND m.user_id = (SELECT auth.uid())
  )
$$;

-- SECURITY DEFINER without search_path, so the viewer's warning has something to report
CREATE FUNCTION public.document_count(org uuid) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER
AS $$
  SELECT count(*) FROM public.documents WHERE organization_id = org
$$;

REVOKE EXECUTE ON FUNCTION public.is_member(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_member(uuid) TO authenticated;
REVOKE EXECUTE ON FUNCTION public.document_count(uuid) FROM PUBLIC, anon;

CREATE FUNCTION public.check_document() RETURNS trigger
LANGUAGE plpgsql SET search_path = ''
AS $$
BEGIN
  IF NEW.status NOT IN ('draft', 'published') THEN
    RAISE EXCEPTION 'invalid status: %', NEW.status;
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.archived AND NEW.title IS DISTINCT FROM OLD.title THEN
    RAISE EXCEPTION 'archived documents cannot be renamed';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER documents_check BEFORE INSERT OR UPDATE ON public.documents
FOR EACH ROW EXECUTE FUNCTION public.check_document();

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.comments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "members read organizations" ON public.organizations
FOR SELECT TO authenticated USING (public.is_member(id));

CREATE POLICY "members manage memberships" ON public.members
FOR ALL TO authenticated USING (public.is_member(organization_id)) WITH CHECK (public.is_member(organization_id));

CREATE POLICY "members access documents" ON public.documents
FOR ALL TO authenticated USING (public.is_member(organization_id)) WITH CHECK (public.is_member(organization_id));

CREATE POLICY "hide archived documents" ON public.documents AS RESTRICTIVE
FOR SELECT TO authenticated USING (NOT archived);

CREATE POLICY "members read comments" ON public.comments
FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM public.documents d WHERE d.id = document_id));

CREATE POLICY "authors add comments" ON public.comments
FOR INSERT TO authenticated WITH CHECK (author_id = (SELECT auth.uid()));

REVOKE ALL ON TABLE public.members FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.comments FROM anon;

CREATE VIEW public.document_titles WITH (security_invoker = true) AS
SELECT id, organization_id, title FROM public.documents;

CREATE VIEW public.organization_names AS
SELECT id, name FROM public.organizations;

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types) VALUES
  ('documents', 'documents', false, 10485760, ARRAY['application/pdf']),
  ('avatars', 'avatars', true, NULL, NULL);

CREATE POLICY "members read document files" ON storage.objects
FOR SELECT TO authenticated
USING (bucket_id = 'documents' AND public.is_member(((storage.foldername(name))[1])::uuid));

CREATE POLICY "users upload their avatar" ON storage.objects
FOR INSERT TO authenticated
WITH CHECK (bucket_id = 'avatars' AND (storage.foldername(name))[1] = (SELECT auth.uid())::text);

COMMIT;
