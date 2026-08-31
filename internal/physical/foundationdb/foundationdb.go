// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Ported to OpenBao by Weftspun. ListPage and interactive Transactional
// added to match the OpenBao physical.Backend / physical.Transactional
// interfaces, which diverged from Vault after the fork.

//go:build foundationdb

package foundationdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/hashicorp/go-hclog"
	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/hashicorp/go-uuid"

	"github.com/apple/foundationdb/bindings/go/src/fdb"
	"github.com/apple/foundationdb/bindings/go/src/fdb/directory"
	"github.com/apple/foundationdb/bindings/go/src/fdb/subspace"
	"github.com/apple/foundationdb/bindings/go/src/fdb/tuple"

	"github.com/openbao/openbao/sdk/v2/physical"
)

const (
	minAPIVersion     = 520
	metaKeysNamespace = "_meta-keys"
	dataNamespace     = "_data"
	lockNamespace     = "_lock"
	dirEntryMarker    = "/\x01"
	dirPathMarker     = "/\x02"
)

var (
	atomicArgOne      = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	atomicArgMinusOne = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

var (
	_ physical.Backend              = (*FDBBackend)(nil)
	_ physical.TransactionalBackend = (*FDBBackend)(nil)
	_ physical.HABackend            = (*FDBBackend)(nil)
	_ physical.Lock                 = (*FDBBackendLock)(nil)
)

type FDBBackend struct {
	logger        log.Logger
	haEnabled     bool
	db            fdb.Database
	metaKeysSpace subspace.Subspace
	dataSpace     subspace.Subspace
	lockSpace     subspace.Subspace
	instanceUUID  string
}

func concat(a []byte, b ...byte) []byte {
	r := make([]byte, len(a)+len(b))
	copy(r, a)
	copy(r[len(a):], b)
	return r
}

func decoratePrefix(prefix string) ([]byte, error) {
	pathElements := strings.Split(prefix, "/")
	decoratedPrefix := strings.Join(pathElements[:len(pathElements)-1], dirPathMarker)
	return []byte(decoratedPrefix + dirEntryMarker), nil
}

func decoratePath(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("invalid empty path")
	}

	path = "/" + path
	isDir := strings.HasSuffix(path, "/")
	path = strings.TrimRight(path, "/")
	lastSlash := strings.LastIndexByte(path, '/')

	decoratedPrefix, err := decoratePrefix(path[:lastSlash+1])
	if err != nil {
		return nil, err
	}

	leaf := path[lastSlash+1:]
	if isDir {
		leaf += "/"
	}

	return concat(decoratedPrefix, []byte(leaf)...), nil
}

func undecoratePath(decoratedPath []byte) string {
	ret := strings.ReplaceAll(string(decoratedPath), dirPathMarker, "/")
	ret = strings.ReplaceAll(ret, dirEntryMarker, "/")
	return strings.TrimLeft(ret, "/")
}

func NewFDBBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	path, ok := conf["path"]
	if !ok {
		path = "vault"
	}
	logger.Debug("config path set", "path", path)
	dirPath := strings.Split(strings.Trim(path, "/"), "/")

	tlsCertFile, hasCertFile := conf["tls_cert_file"]
	tlsKeyFile, hasKeyFile := conf["tls_key_file"]
	tlsCAFile, hasCAFile := conf["tls_ca_file"]
	tlsEnabled := hasCertFile && hasKeyFile && hasCAFile

	if (hasCertFile || hasKeyFile || hasCAFile) && !tlsEnabled {
		return nil, fmt.Errorf("FoundationDB TLS requires all 3 of tls_cert_file, tls_key_file, and tls_ca_file")
	}

	tlsVerifyPeers, ok := conf["tls_verify_peers"]
	if !ok && tlsEnabled {
		return nil, fmt.Errorf("required option tls_verify_peers not set in configuration")
	}

	fdbApiVersionStr, ok := conf["api_version"]
	if !ok {
		return nil, fmt.Errorf("FoundationDB API version not specified")
	}

	fdbApiVersionInt, err := strconv.Atoi(fdbApiVersionStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse api_version parameter: %w", err)
	}

	if fdbApiVersionInt < minAPIVersion {
		return nil, fmt.Errorf("configured FoundationDB API version lower than minimum required version: %d < %d", fdbApiVersionInt, minAPIVersion)
	}
	logger.Debug("FoundationDB API version set", "fdb_api_version", fdbApiVersionInt)

	fdbClusterFile, ok := conf["cluster_file"]
	if !ok {
		return nil, fmt.Errorf("FoundationDB cluster file not specified")
	}

	haEnabled := false
	haEnabledStr, ok := conf["ha_enabled"]
	if ok {
		haEnabled, err = strconv.ParseBool(haEnabledStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ha_enabled parameter: %w", err)
		}
	}

	instanceUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not generate instance UUID: %w", err)
	}
	logger.Debug("Instance UUID", "uuid", instanceUUID)

	if err := fdb.APIVersion(fdbApiVersionInt); err != nil {
		return nil, fmt.Errorf("failed to set FDB API version: %w", err)
	}

	if tlsEnabled {
		opts := fdb.Options()

		tlsPassword, ok := conf["tls_password"]
		if ok {
			err := opts.SetTLSPassword(tlsPassword)
			if err != nil {
				return nil, fmt.Errorf("failed to set TLS password: %w", err)
			}
		}

		err := opts.SetTLSCaPath(tlsCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to set TLS CA bundle path: %w", err)
		}

		err = opts.SetTLSCertPath(tlsCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to set TLS certificate path: %w", err)
		}

		err = opts.SetTLSKeyPath(tlsKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to set TLS key path: %w", err)
		}

		err = opts.SetTLSVerifyPeers([]byte(tlsVerifyPeers))
		if err != nil {
			return nil, fmt.Errorf("failed to set TLS peer verification criteria: %w", err)
		}
	}

	db, err := fdb.Open(fdbClusterFile, []byte("DB"))
	if err != nil {
		return nil, fmt.Errorf("failed to open database with cluster file %q: %w", fdbClusterFile, err)
	}

	topDir, err := directory.CreateOrOpen(db, dirPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create/open top-level directory %q: %w", path, err)
	}

	f := &FDBBackend{
		logger:        logger,
		haEnabled:     haEnabled,
		db:            db,
		metaKeysSpace: topDir.Sub(metaKeysNamespace),
		dataSpace:     topDir.Sub(dataNamespace),
		lockSpace:     topDir.Sub(lockNamespace),
		instanceUUID:  instanceUUID,
	}
	return f, nil
}

func (f *FDBBackend) incDirsRefcount(tr fdb.Transaction, path string) error {
	pathElements := strings.Split(strings.TrimRight(path, "/"), "/")

	for i := len(pathElements) - 1; i != 0; i-- {
		dPath, err := decoratePath(strings.Join(pathElements[:i], "/") + "/")
		if err != nil {
			return fmt.Errorf("error incrementing directories refcount: %w", err)
		}

		tr.Add(fdb.Key(concat(f.metaKeysSpace.Bytes(), dPath...)), atomicArgOne)
		tr.Add(fdb.Key(concat(f.dataSpace.Bytes(), dPath...)), atomicArgOne)
	}

	return nil
}

type dirsDecTodo struct {
	fkey   fdb.Key
	future fdb.FutureByteSlice
}

func (f *FDBBackend) decDirsRefcount(tr fdb.Transaction, path string) error {
	pathElements := strings.Split(strings.TrimRight(path, "/"), "/")
	dirsTodo := make([]dirsDecTodo, 0, len(pathElements)*2)

	for i := len(pathElements) - 1; i != 0; i-- {
		dPath, err := decoratePath(strings.Join(pathElements[:i], "/") + "/")
		if err != nil {
			return fmt.Errorf("error decrementing directories refcount: %w", err)
		}

		metaFKey := fdb.Key(concat(f.metaKeysSpace.Bytes(), dPath...))
		dirsTodo = append(dirsTodo, dirsDecTodo{
			fkey:   metaFKey,
			future: tr.Get(metaFKey),
		})

		dataFKey := fdb.Key(concat(f.dataSpace.Bytes(), dPath...))
		dirsTodo = append(dirsTodo, dirsDecTodo{
			fkey:   dataFKey,
			future: tr.Get(dataFKey),
		})
	}

	for _, todo := range dirsTodo {
		value, err := todo.future.Get()
		if err != nil {
			return fmt.Errorf("error getting directory refcount while decrementing: %w", err)
		}

		if value == nil {
			return fmt.Errorf("non-existent directory while decrementing directory refcount")
		}

		var count int64
		err = binary.Read(bytes.NewReader(value), binary.LittleEndian, &count)
		if err != nil {
			return fmt.Errorf("error reading directory refcount while decrementing: %w", err)
		}

		if count > 1 {
			tr.Add(todo.fkey, atomicArgMinusOne)
		} else {
			tr.Clear(todo.fkey)
		}
	}

	return nil
}

func (f *FDBBackend) internalPut(tr fdb.Transaction, decoratedPath []byte, path string, value []byte) error {
	metaFKey := fdb.Key(concat(f.metaKeysSpace.Bytes(), decoratedPath...))
	metaFuture := tr.Get(metaFKey)

	dataFKey := fdb.Key(concat(f.dataSpace.Bytes(), decoratedPath...))
	tr.Set(dataFKey, value)

	value, err := metaFuture.Get()
	if err != nil {
		return fmt.Errorf("put error while getting meta key: %w", err)
	}

	if value == nil {
		tr.Set(metaFKey, []byte{})
		return f.incDirsRefcount(tr, path)
	}

	return nil
}

func (f *FDBBackend) internalClear(tr fdb.Transaction, decoratedPath []byte, path string) error {
	metaFKey := fdb.Key(concat(f.metaKeysSpace.Bytes(), decoratedPath...))

	value, err := tr.Get(metaFKey).Get()
	if err != nil {
		return fmt.Errorf("delete error while getting meta key: %w", err)
	}

	if value != nil {
		dataFKey := fdb.Key(concat(f.dataSpace.Bytes(), decoratedPath...))
		tr.Clear(dataFKey)
		tr.Clear(metaFKey)
		return f.decDirsRefcount(tr, path)
	}

	return nil
}

func (f *FDBBackend) Put(ctx context.Context, entry *physical.Entry) error {
	defer metrics.MeasureSince([]string{"foundationdb", "put"}, time.Now())

	decoratedPath, err := decoratePath(entry.Key)
	if err != nil {
		return fmt.Errorf("could not build decorated path to put item %s: %w", entry.Key, err)
	}

	_, err = f.db.Transact(func(tr fdb.Transaction) (interface{}, error) {
		return nil, f.internalPut(tr, decoratedPath, entry.Key, entry.Value)
	})

	if err != nil {
		return fmt.Errorf("put failed for item %s: %w", entry.Key, err)
	}

	return nil
}

func (f *FDBBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	defer metrics.MeasureSince([]string{"foundationdb", "get"}, time.Now())

	decoratedPath, err := decoratePath(key)
	if err != nil {
		return nil, fmt.Errorf("could not build decorated path to get item %s: %w", key, err)
	}

	fkey := fdb.Key(concat(f.dataSpace.Bytes(), decoratedPath...))

	value, err := f.db.ReadTransact(func(rtr fdb.ReadTransaction) (interface{}, error) {
		value, err := rtr.Get(fkey).Get()
		if err != nil {
			return nil, err
		}
		return value, nil
	})
	if err != nil {
		return nil, fmt.Errorf("get failed for item %s: %w", key, err)
	}
	if value.([]byte) == nil {
		return nil, nil
	}

	return &physical.Entry{
		Key:   key,
		Value: value.([]byte),
	}, nil
}

func (f *FDBBackend) Delete(ctx context.Context, key string) error {
	defer metrics.MeasureSince([]string{"foundationdb", "delete"}, time.Now())

	decoratedPath, err := decoratePath(key)
	if err != nil {
		return fmt.Errorf("could not build decorated path to delete item %s: %w", key, err)
	}

	_, err = f.db.Transact(func(tr fdb.Transaction) (interface{}, error) {
		return nil, f.internalClear(tr, decoratedPath, key)
	})

	if err != nil {
		return fmt.Errorf("delete failed for item %s: %w", key, err)
	}

	return nil
}

func (f *FDBBackend) List(ctx context.Context, prefix string) ([]string, error) {
	defer metrics.MeasureSince([]string{"foundationdb", "list"}, time.Now())

	prefix = strings.TrimRight("/"+prefix, "/") + "/"

	decoratedPrefix, err := decoratePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("could not build decorated path to list prefix %s: %w", prefix, err)
	}

	rangeBegin := fdb.Key(concat(f.metaKeysSpace.Bytes(), decoratedPrefix...))
	rangeEnd := fdb.Key(concat(rangeBegin, 0xff))
	pathRange := fdb.KeyRange{Begin: rangeBegin, End: rangeEnd}
	keyPrefixLen := len(rangeBegin)

	content, err := f.db.ReadTransact(func(rtr fdb.ReadTransaction) (interface{}, error) {
		dirList := make([]string, 0)
		ri := rtr.GetRange(pathRange, fdb.RangeOptions{Mode: fdb.StreamingModeWantAll}).Iterator()

		for ri.Advance() {
			kv := ri.MustGet()
			dirList = append(dirList, string(kv.Key[keyPrefixLen:]))
		}

		return dirList, nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not list prefix %s: %w", prefix, err)
	}

	return content.([]string), nil
}

func (f *FDBBackend) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	defer metrics.MeasureSince([]string{"foundationdb", "list-page"}, time.Now())

	prefix = strings.TrimRight("/"+prefix, "/") + "/"

	decoratedPrefix, err := decoratePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("could not build decorated path to list prefix %s: %w", prefix, err)
	}

	rangeBegin := fdb.Key(concat(f.metaKeysSpace.Bytes(), decoratedPrefix...))
	keyPrefixLen := len(rangeBegin)

	if after != "" {
		rangeBegin = fdb.Key(concat(rangeBegin, []byte(after)...))
		rangeBegin = append(rangeBegin, 0x00)
	}

	rangeEnd := fdb.Key(concat(f.metaKeysSpace.Bytes(), decoratedPrefix...))
	rangeEnd = append(rangeEnd, 0xff)
	pathRange := fdb.KeyRange{Begin: rangeBegin, End: rangeEnd}

	fdbLimit := 0
	if limit > 0 {
		fdbLimit = limit
	}

	content, err := f.db.ReadTransact(func(rtr fdb.ReadTransaction) (interface{}, error) {
		dirList := make([]string, 0)
		opts := fdb.RangeOptions{Mode: fdb.StreamingModeWantAll}
		if fdbLimit > 0 {
			opts.Limit = fdbLimit
		}
		ri := rtr.GetRange(pathRange, opts).Iterator()

		for ri.Advance() {
			kv := ri.MustGet()
			dirList = append(dirList, string(kv.Key[keyPrefixLen:]))
		}

		return dirList, nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not list page prefix %s: %w", prefix, err)
	}

	return content.([]string), nil
}

// --- Interactive Transactional interface ---

type fdbTransaction struct {
	l        sync.Mutex
	f        *FDBBackend
	tr       fdb.Transaction
	readOnly bool
	finished bool
}

func (f *FDBBackend) BeginTx(ctx context.Context) (physical.Transaction, error) {
	tr, err := f.db.CreateTransaction()
	if err != nil {
		return nil, fmt.Errorf("failed to create FDB transaction: %w", err)
	}

	return &fdbTransaction{
		f:        f,
		tr:       tr,
		readOnly: false,
	}, nil
}

func (f *FDBBackend) BeginReadOnlyTx(ctx context.Context) (physical.Transaction, error) {
	tr, err := f.db.CreateTransaction()
	if err != nil {
		return nil, fmt.Errorf("failed to create FDB read-only transaction: %w", err)
	}

	return &fdbTransaction{
		f:        f,
		tr:       tr,
		readOnly: true,
	}, nil
}

func (t *fdbTransaction) Put(ctx context.Context, entry *physical.Entry) error {
	t.l.Lock()
	defer t.l.Unlock()

	if t.readOnly {
		return physical.ErrTransactionReadOnly
	}
	if t.finished {
		return physical.ErrTransactionAlreadyCommitted
	}

	decoratedPath, err := decoratePath(entry.Key)
	if err != nil {
		return fmt.Errorf("could not build decorated path: %w", err)
	}

	return t.f.internalPut(t.tr, decoratedPath, entry.Key, entry.Value)
}

func (t *fdbTransaction) Get(ctx context.Context, key string) (*physical.Entry, error) {
	t.l.Lock()
	defer t.l.Unlock()

	if t.finished {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	decoratedPath, err := decoratePath(key)
	if err != nil {
		return nil, fmt.Errorf("could not build decorated path: %w", err)
	}

	fkey := fdb.Key(concat(t.f.dataSpace.Bytes(), decoratedPath...))
	value, err := t.tr.Get(fkey).Get()
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}

	return &physical.Entry{
		Key:   key,
		Value: value,
	}, nil
}

func (t *fdbTransaction) Delete(ctx context.Context, key string) error {
	t.l.Lock()
	defer t.l.Unlock()

	if t.readOnly {
		return physical.ErrTransactionReadOnly
	}
	if t.finished {
		return physical.ErrTransactionAlreadyCommitted
	}

	decoratedPath, err := decoratePath(key)
	if err != nil {
		return fmt.Errorf("could not build decorated path: %w", err)
	}

	return t.f.internalClear(t.tr, decoratedPath, key)
}

func (t *fdbTransaction) List(ctx context.Context, prefix string) ([]string, error) {
	t.l.Lock()
	defer t.l.Unlock()

	if t.finished {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	prefix = strings.TrimRight("/"+prefix, "/") + "/"
	decoratedPrefix, err := decoratePrefix(prefix)
	if err != nil {
		return nil, err
	}

	rangeBegin := fdb.Key(concat(t.f.metaKeysSpace.Bytes(), decoratedPrefix...))
	rangeEnd := fdb.Key(concat(rangeBegin, 0xff))
	pathRange := fdb.KeyRange{Begin: rangeBegin, End: rangeEnd}
	keyPrefixLen := len(rangeBegin)

	dirList := make([]string, 0)
	ri := t.tr.GetRange(pathRange, fdb.RangeOptions{Mode: fdb.StreamingModeWantAll}).Iterator()

	for ri.Advance() {
		kv := ri.MustGet()
		dirList = append(dirList, string(kv.Key[keyPrefixLen:]))
	}

	return dirList, nil
}

func (t *fdbTransaction) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	t.l.Lock()
	defer t.l.Unlock()

	if t.finished {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	prefix = strings.TrimRight("/"+prefix, "/") + "/"
	decoratedPrefix, err := decoratePrefix(prefix)
	if err != nil {
		return nil, err
	}

	rangeBegin := fdb.Key(concat(t.f.metaKeysSpace.Bytes(), decoratedPrefix...))
	keyPrefixLen := len(rangeBegin)

	if after != "" {
		rangeBegin = fdb.Key(concat(rangeBegin, []byte(after)...))
		rangeBegin = append(rangeBegin, 0x00)
	}

	rangeEnd := fdb.Key(concat(t.f.metaKeysSpace.Bytes(), decoratedPrefix...))
	rangeEnd = append(rangeEnd, 0xff)
	pathRange := fdb.KeyRange{Begin: rangeBegin, End: rangeEnd}

	opts := fdb.RangeOptions{Mode: fdb.StreamingModeWantAll}
	if limit > 0 {
		opts.Limit = limit
	}

	dirList := make([]string, 0)
	ri := t.tr.GetRange(pathRange, opts).Iterator()

	for ri.Advance() {
		kv := ri.MustGet()
		dirList = append(dirList, string(kv.Key[keyPrefixLen:]))
	}

	return dirList, nil
}

func (t *fdbTransaction) Commit(ctx context.Context) error {
	if t.readOnly {
		return t.Rollback(ctx)
	}

	t.l.Lock()
	defer t.l.Unlock()

	if t.finished {
		return physical.ErrTransactionAlreadyCommitted
	}

	t.finished = true

	err := t.tr.Commit().Get()
	if err != nil {
		return fmt.Errorf("%v: %w", err, physical.ErrTransactionCommitFailure)
	}

	return nil
}

func (t *fdbTransaction) Rollback(ctx context.Context) error {
	t.l.Lock()
	defer t.l.Unlock()

	if t.finished {
		return physical.ErrTransactionAlreadyCommitted
	}

	t.finished = true
	t.tr.Cancel()

	return nil
}

// --- HA Lock ---

type FDBBackendLock struct {
	f     *FDBBackend
	key   string
	value string
	fkey  fdb.Key
	lock  sync.Mutex
}

func (f *FDBBackend) LockWith(key, value string) (physical.Lock, error) {
	return &FDBBackendLock{
		f:     f,
		key:   key,
		value: value,
		fkey:  f.lockSpace.Pack(tuple.Tuple{key}),
	}, nil
}

func (f *FDBBackend) HAEnabled() bool {
	return f.haEnabled
}

const (
	lockContentValueIdx   = 0
	lockContentOwnerIdx   = 1
	lockContentExpiresIdx = 2
	lockTupleContentElts  = 3
	lockTTL                  = 15 * time.Second
	lockRenewInterval        = 5 * time.Second
	lockAcquireRetryInterval = 5 * time.Second
)

type fdbBackendLockContent struct {
	value     string
	ownerUUID string
	expires   time.Time
}

func packLock(content *fdbBackendLockContent) []byte {
	t := tuple.Tuple{content.value, content.ownerUUID, content.expires.UnixNano()}
	return t.Pack()
}

func unpackLock(tupleContent []byte) (*fdbBackendLockContent, error) {
	t, err := tuple.Unpack(tupleContent)
	if err != nil {
		return nil, err
	}

	if len(t) != lockTupleContentElts {
		return nil, fmt.Errorf("unexpected lock content, len %d != %d", len(t), lockTupleContentElts)
	}

	return &fdbBackendLockContent{
		value:     t[lockContentValueIdx].(string),
		ownerUUID: t[lockContentOwnerIdx].(string),
		expires:   time.Unix(0, t[lockContentExpiresIdx].(int64)),
	}, nil
}

func (fl *FDBBackendLock) getLockContent(tr fdb.Transaction) (*fdbBackendLockContent, error) {
	tupleContent, err := tr.Get(fl.fkey).Get()
	if err != nil {
		return nil, err
	}

	if tupleContent == nil {
		return nil, fmt.Errorf("non-existent lock %s", fl.key)
	}

	content, err := unpackLock(tupleContent)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack lock %s: %w", fl.key, err)
	}

	return content, nil
}

func (fl *FDBBackendLock) setLockContent(tr fdb.Transaction, content *fdbBackendLockContent) {
	tr.Set(fl.fkey, packLock(content))
}

func (fl *FDBBackendLock) isOwned(content *fdbBackendLockContent) bool {
	return content.ownerUUID == fl.f.instanceUUID
}

func (fl *FDBBackendLock) isExpired(content *fdbBackendLockContent) bool {
	return time.Now().After(content.expires)
}

func (fl *FDBBackendLock) acquireTryLock(acquired chan struct{}, errors chan error) (bool, error) {
	wonTheRace, err := fl.f.db.Transact(func(tr fdb.Transaction) (interface{}, error) {
		tupleContent, err := tr.Get(fl.fkey).Get()
		if err != nil {
			return nil, fmt.Errorf("could not read lock: %w", err)
		}

		if tupleContent != nil {
			content, err := unpackLock(tupleContent)
			if err != nil {
				return nil, fmt.Errorf("failed to unpack lock %s: %w", fl.key, err)
			}

			if fl.isOwned(content) {
				return nil, fmt.Errorf("lock %s already held", fl.key)
			}

			if !fl.isExpired(content) {
				return false, nil
			}
		}

		content := &fdbBackendLockContent{
			value:     fl.value,
			ownerUUID: fl.f.instanceUUID,
			expires:   time.Now().Add(lockTTL),
		}

		fl.setLockContent(tr, content)

		return true, nil
	})
	if err != nil {
		errors <- err
		return false, err
	}

	if wonTheRace.(bool) {
		close(acquired)
	}

	return wonTheRace.(bool), nil
}

func (fl *FDBBackendLock) acquireLock(abandon chan struct{}, acquired chan struct{}, errors chan error) {
	ticker := time.NewTicker(lockAcquireRetryInterval)
	defer ticker.Stop()

	lockAcquired, err := fl.acquireTryLock(acquired, errors)
	if lockAcquired || err != nil {
		return
	}

	for {
		select {
		case <-abandon:
			return
		case <-ticker.C:
			lockAcquired, err := fl.acquireTryLock(acquired, errors)
			if lockAcquired || err != nil {
				return
			}
		}
	}
}

func (fl *FDBBackendLock) maintainLock(lost <-chan struct{}) {
	ticker := time.NewTicker(lockRenewInterval)
	for {
		select {
		case <-ticker.C:
			_, err := fl.f.db.Transact(func(tr fdb.Transaction) (interface{}, error) {
				content, err := fl.getLockContent(tr)
				if err != nil {
					return nil, err
				}

				if !fl.isOwned(content) {
					return nil, fmt.Errorf("lost lock %s", fl.key)
				}

				if fl.isExpired(content) {
					return nil, fmt.Errorf("lock %s expired", fl.key)
				}

				content.expires = time.Now().Add(lockTTL)
				fl.setLockContent(tr, content)

				return nil, nil
			})
			if err != nil {
				fl.f.logger.Error("lock maintain", "error", err)
			}
		case <-lost:
			ticker.Stop()
			return
		}
	}
}

func (fl *FDBBackendLock) watchLock(lost chan struct{}) {
	for {
		watch, err := fl.f.db.Transact(func(tr fdb.Transaction) (interface{}, error) {
			content, err := fl.getLockContent(tr)
			if err != nil {
				return nil, err
			}

			if !fl.isOwned(content) {
				return nil, fmt.Errorf("lost lock %s", fl.key)
			}

			if fl.isExpired(content) {
				return nil, fmt.Errorf("lock %s expired", fl.key)
			}

			future := tr.Watch(fl.fkey)
			return future, nil
		})
		if err != nil {
			fl.f.logger.Error("lock watch", "error", err)
			break
		}

		watch.(fdb.FutureNil).Get()
	}

	close(lost)
}

func (fl *FDBBackendLock) Lock(stopCh <-chan struct{}) (<-chan struct{}, error) {
	fl.lock.Lock()
	defer fl.lock.Unlock()

	var (
		lost     = make(chan struct{})
		abandon  = make(chan struct{})
		acquired = make(chan struct{})
		errors   = make(chan error)
	)

	go fl.acquireLock(abandon, acquired, errors)

	select {
	case <-acquired:
		go fl.maintainLock(lost)
		go fl.watchLock(lost)
	case err := <-errors:
		close(abandon)
		return nil, err
	case <-stopCh:
		close(abandon)
		return nil, nil
	}

	return lost, nil
}

func (fl *FDBBackendLock) Unlock() error {
	fl.lock.Lock()
	defer fl.lock.Unlock()

	_, err := fl.f.db.Transact(func(tr fdb.Transaction) (interface{}, error) {
		content, err := fl.getLockContent(tr)
		if err != nil {
			return nil, fmt.Errorf("could not get lock content: %w", err)
		}

		if !fl.isOwned(content) {
			return nil, nil
		}

		tr.Clear(fl.fkey)
		return nil, nil
	})
	if err != nil {
		return fmt.Errorf("unlock failed: %w", err)
	}

	return nil
}

func (fl *FDBBackendLock) Value() (bool, string, error) {
	tupleContent, err := fl.f.db.ReadTransact(func(rtr fdb.ReadTransaction) (interface{}, error) {
		tupleContent, err := rtr.Get(fl.fkey).Get()
		if err != nil {
			return nil, fmt.Errorf("could not read lock: %w", err)
		}
		return tupleContent, nil
	})
	if err != nil {
		return false, "", fmt.Errorf("get lock value failed for lock %s: %w", fl.key, err)
	}
	if tupleContent.([]byte) == nil {
		return false, "", nil
	}

	content, err := unpackLock(tupleContent.([]byte))
	if err != nil {
		return false, "", fmt.Errorf("get lock value failed to unpack lock %s: %w", fl.key, err)
	}

	return true, content.value, nil
}
