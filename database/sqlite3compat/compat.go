// Package sqlite3compat registers the pure-Go modernc.org/sqlite driver under
// the name "sqlite3" so it is a drop-in replacement for the CGo-based
// github.com/mattn/go-sqlite3.  Import this package with a blank identifier:
//
//	import _ "github.com/kgretzky/evilginx2/database/sqlite3compat"
package sqlite3compat

import (
	"database/sql"
	"database/sql/driver"

	"modernc.org/sqlite"
)

func init() {
	sql.Register("sqlite3", &wrappedDriver{})
}

// wrappedDriver delegates to modernc.org/sqlite.Driver but is registered
// under the "sqlite3" name instead of "sqlite".
type wrappedDriver struct {
	d sqlite.Driver
}

func (w *wrappedDriver) Open(name string) (driver.Conn, error) {
	return w.d.Open(name)
}
