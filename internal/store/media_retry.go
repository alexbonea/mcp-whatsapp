package store

import (
	"context"
	"errors"
)

// GetMediaRetrySource scopes the original sender/direction to both message ID
// and chat. Message IDs alone are not a cache identity.
func (s *Store) GetMediaRetrySource(ctx context.Context, id, chatJID string) (m Message, err error) {
	m.ID, m.ChatJID = id, chatJID
	err = s.db.QueryRowContext(ctx,
		"SELECT sender, timestamp, is_from_me FROM messages WHERE id = ? AND chat_jid = ?", id, chatJID,
	).Scan(&m.Sender, &m.Timestamp, &m.IsFromMe)
	return
}

// UpdateMediaDirectPath changes only the download address, and only if the
// encrypted attachment has not been replaced while recovery was in flight.
// The original URL remains provenance; download prefers direct_path.
func (s *Store) UpdateMediaDirectPath(ctx context.Context, id, chatJID, directPath string, mediaKey, sha, encSHA []byte) error {
	result, err := s.db.ExecContext(ctx, `UPDATE messages SET direct_path = ?
		WHERE id = ? AND chat_jid = ? AND media_key = ? AND file_sha256 = ? AND file_enc_sha256 = ?`,
		directPath, id, chatJID, mediaKey, sha, encSHA)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return errors.New("media metadata changed during recovery")
	}
	return err
}
