package ldbbolt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"

	"github.com/libregraph/idm/pkg/ldapdn"
)

var logger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &logrus.TextFormatter{},
	Level:     logrus.InfoLevel,
}

var baseEntry = ldap.NewEntry("o=base",
	map[string][]string{
		"o":           {"base"},
		"objectclass": {"organization"},
	})
var subEntry = ldap.NewEntry("ou=sub,o=base",
	map[string][]string{
		"ou":          {"sub"},
		"objectclass": {"organizationalUnit"},
	})
var userEntry = ldap.NewEntry("uid=user,ou=sub,o=base",
	map[string][]string{
		"uid":         {"user"},
		"displayname": {"DisplayName"},
		"mail":        {"user@example"},
		"entryuuid":   {"abcd-defg"},
	})
var otherUserEntry = ldap.NewEntry("uid=user1,ou=sub,o=base",
	map[string][]string{
		"uid":         {"user1"},
		"displayname": {"DisplayName"},
		"mail":        {"user@example"},
		"entryuuid":   {"abcd-defg"},
	})

func setupTestDB(t *testing.T) *LdbBolt {
	bdb := &LdbBolt{}

	dbFile, err := ioutil.TempFile("", "ldbbolt_")
	if err != nil {
		t.Fatalf("Error creating tempfile: %s", err)
	}
	defer dbFile.Close()
	if err := bdb.Configure(logger, "o=base", dbFile.Name(), nil); err != nil {
		t.Fatalf("Error setting up database %s", err)
	}
	if err := bdb.Initialize(); err != nil {
		t.Fatalf("Error initializing database %s", err)
	}
	return bdb
}

func addTestData(bdb *LdbBolt, t *testing.T) {
	// add	sample data
	for _, entry := range []*ldap.Entry{baseEntry, subEntry, userEntry, otherUserEntry} {
		if err := bdb.EntryPut(entry); err != nil {
			t.Fatalf("Failed to popluate test database: %s", err)
		}
	}
}

func TestEntryPutSingle(t *testing.T) {
	bdb := setupTestDB(t)
	defer os.Remove(bdb.db.Path())
	defer bdb.Close()

	// adding wrong base entry fails
	if err := bdb.EntryPut(subEntry); err == nil {
		t.Fatal("Adding wrong base entry should fail")
	}

	// adding base entry succeeds
	if err := bdb.EntryPut(baseEntry); err != nil {
		t.Fatalf("Adding correct base entry should succeed. Got error:%s", err)
	}

	// adding the same entry again fails
	err := bdb.EntryPut(baseEntry)
	if err == nil || !errors.Is(err, ErrEntryAlreadyExists) {
		t.Fatalf("Adding the same entry	twice should fail with %v, got: %v", ErrEntryAlreadyExists, err)
	}

	// adding entry without parent fails
	if err := bdb.EntryPut(userEntry); err == nil {
		t.Fatal("Adding entry without parent should fail")
	}
}

func TestEntryPutMulti(t *testing.T) {
	bdb := setupTestDB(t)
	defer os.Remove(bdb.db.Path())
	defer bdb.Close()

	// adding multiple entries succeeds
	for _, entry := range []*ldap.Entry{baseEntry, subEntry, userEntry} {
		if err := bdb.EntryPut(entry); err != nil {
			t.Fatalf("Adding more entries should succeed. Got error:%s", err)
		}
	}
	_ = bdb.db.View(func(tx *bolt.Tx) error {
		id2entry := tx.Bucket([]byte("id2entry"))
		var i int
		_ = id2entry.ForEach(func(_, _ []byte) error {
			i++
			return nil
		})
		if i != 3 {
			t.Errorf("id2enty should have exactly 3 entries now")
		}
		i = 0
		dn2id := tx.Bucket([]byte("dn2id"))
		_ = dn2id.ForEach(func(_, _ []byte) error {
			i++
			return nil
		})
		if i != 3 {
			t.Errorf("dn2id should have exactly 3 entries now")
		}

		// get id of leaf entry, this should not be present
		// as a key in the id2children bucket. See test below.
		dn, _ := ldapdn.ParseNormalize(userEntry.DN)
		leafID := dn2id.Get([]byte(dn))

		i = 0
		id2children := tx.Bucket([]byte("id2children"))
		_ = id2children.ForEach(func(id, v []byte) error {
			i++
			if binary.LittleEndian.Uint64(id) == binary.LittleEndian.Uint64(leafID) {
				t.Errorf("id2children should not have items for leaf entries")
			} else if len(v) != 8 {
				t.Errorf("id2children each id should have exactly one 8	byte entry currently")
			}
			return nil
		})
		if i != 2 {
			t.Errorf("dn2id should have exactly 2 entries currently")
		}
		return nil
	})
}

func TestEntryDeleteFails(t *testing.T) {
	bdb := setupTestDB(t)
	defer os.Remove(bdb.db.Path())
	defer bdb.Close()
	addTestData(bdb, t)

	// Deleting non existing entry fails
	err := bdb.EntryDelete("cn=doesnotexist,ou=sub,o=base")
	if err == nil || !errors.Is(err, ErrEntryNotFound) {
		t.Errorf("Expected '%v' got: '%v'", ErrEntryNotFound, err)
	}

	// Deleting intermediate entry fails
	err = bdb.EntryDelete("ou=sub,o=base")
	if err == nil || !errors.Is(err, ErrNonLeafEntry) {
		t.Errorf("Expected '%v' got: '%v'", ErrNonLeafEntry, err)
	}
}

func TestEntryDeleteSucceeds(t *testing.T) {
	bdb := setupTestDB(t)
	defer os.Remove(bdb.db.Path())
	defer bdb.Close()
	addTestData(bdb, t)
	// Get EntryID for later checks
	var entryID uint64
	_ = bdb.db.View(func(tx *bolt.Tx) error {
		entryID = bdb.getIDByDN(tx, "uid=user,ou=sub,o=base")
		return nil
	})

	// Delete on an existing leaf entry succeeds
	err := bdb.EntryDelete("uid=user,ou=sub,o=base")
	if err != nil {
		t.Errorf("Expected success got '%v'", err)
	}
	// Make sure it's really gone
	// a) from dn2id
	err = bdb.db.View(func(tx *bolt.Tx) error {
		if id := bdb.getIDByDN(tx, "uid=user,ou=sub,o=base"); id != 0 {
			return errors.New("delete failed")
		}
		return nil
	})
	if err != nil {
		t.Errorf("Expected entry to be gone from dn2id bucket.")
	}
	// b) from id2entry
	err = bdb.db.View(func(tx *bolt.Tx) error {
		id2entry := tx.Bucket([]byte("id2entry"))
		if e := id2entry.Get(idToBytes(entryID)); len(e) != 0 {
			return errors.New("delete failed")
		}
		return nil
	})
	if err != nil {
		t.Errorf("Expected entry to be gone from id2entry bucket.")
	}
	// and c) from id2children values
	_ = bdb.db.View(func(tx *bolt.Tx) error {
		id2children := tx.Bucket([]byte("id2children"))
		err = id2children.ForEach(func(id, v []byte) error {
			r := bytes.NewReader(v)
			ids := make([]uint64, len(v)/8)
			if innerErr := binary.Read(r, binary.LittleEndian, &ids); innerErr != nil {
				return innerErr
			}
			for _, id := range ids {
				if id == entryID {
					return errors.New("delete failed")
				}
			}
			return nil
		})
		return err
	})
	if err != nil {
		t.Errorf("Expected entry to be gone from values in id2children bucket.")
	}
}
