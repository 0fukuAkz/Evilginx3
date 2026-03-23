
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE campaigns ADD COLUMN encryption_key varchar(255);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

