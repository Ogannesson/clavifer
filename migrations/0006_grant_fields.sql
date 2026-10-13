-- NULL fields_json grants every field of the credential; a JSON array limits the grant to that subset.
ALTER TABLE grants ADD COLUMN fields_json TEXT;
