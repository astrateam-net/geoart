-- The provider requires the ID token as id_token_hint to honour post_logout_redirect_uri.
ALTER TABLE oidc_sessions ADD COLUMN id_token TEXT;
