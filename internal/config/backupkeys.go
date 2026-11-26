package config

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/backup"
)

type PendingKey struct {
	Phrase string `json:"phrase"`
	KeyID  string `json:"keyId"`
	Format string `json:"format"`
	Nonce  string `json:"nonce"`
}

func (store *Store) GenerateKey(ctx context.Context, owner string) (PendingKey, error) {
	if owner == "" {
		return PendingKey{}, errors.New("Schlüsselerzeugung erfordert eine Anmeldung")
	}
	key, err := backup.GenerateKey()
	if err != nil {
		return PendingKey{}, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return PendingKey{}, err
	}
	pending := PendingKey{Phrase: key.Phrase, KeyID: key.KeyID, Format: key.Format, Nonce: base64.RawURLEncoding.EncodeToString(nonce[:])}
	now := time.Now()

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return PendingKey{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM pending_backup_keys WHERE expires<?`, float64(now.UnixMilli())/1000); err != nil {
		return PendingKey{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO pending_backup_keys(nonce,owner,expires,revision,password,key_id,format)
		SELECT ?,?,?,revision,?,?,? FROM configuration WHERE id=1`, pending.Nonce, owner,
		float64(now.Add(15*time.Minute).UnixMilli())/1000, key.Password, key.KeyID, key.Format)
	if err != nil {
		return PendingKey{}, err
	}
	if err := tx.Commit(); err != nil {
		return PendingKey{}, err
	}
	return pending, nil
}

func (store *Store) ActivateKey(ctx context.Context, owner, nonce string, writtenDown, acknowledgeOld bool) error {
	if !writtenDown {
		return errors.New("Bitte bestätigen, dass die Phrase sicher notiert wurde")
	}
	if owner == "" || len(nonce) != 43 {
		return ErrConflict
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Take the writer lock before reading settings. A rollback preserves the
	// pending key if the rotation is not confirmed or saving fails.
	var password, keyID, format string
	err = tx.QueryRowContext(ctx, `DELETE FROM pending_backup_keys
		WHERE nonce=? AND owner=? AND expires>? AND revision=(SELECT revision FROM configuration WHERE id=1)
		RETURNING password,key_id,format`, nonce, owner, float64(time.Now().UnixMilli())/1000).
		Scan(&password, &keyID, &format)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}

	var stored []byte
	if err := tx.QueryRowContext(ctx, `SELECT settings FROM configuration WHERE id=1`).Scan(&stored); err != nil {
		return err
	}
	values, err := decodeValues(stored)
	if err != nil {
		return err
	}
	if values.String("BACKUP_ARCHIVE_PASSWORD") != "" && !acknowledgeOld {
		return errors.New("Alte Sicherungen benötigen weiterhin ihre alte Phrase bzw. ihr altes Passwort; ohne diese sind deren Daten verloren")
	}

	values["BACKUP_ARCHIVE_PASSWORD"] = password
	values["BACKUP_KEY_ID"] = keyID
	values["BACKUP_KEY_FORMAT"] = format
	values["BACKUP_NAMESPACE"] = "keys/" + keyID
	values["BACKUP_ENCRYPTION_ENABLED"] = true
	encoded, err := json.Marshal(values)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE configuration SET settings=?,revision=revision+1 WHERE id=1`, string(encoded)); err != nil {
		return err
	}
	return tx.Commit()
}
