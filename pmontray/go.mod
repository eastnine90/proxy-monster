module github.com/ridi-oss/proxy-monster/pmontray

go 1.23

require (
	fyne.io/systray v1.12.2
	github.com/ridi-oss/proxy-monster/pmon v0.0.0
)

require (
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
)

// In-repo module: resolve locally (no go.work needed for CI / fresh clones).
replace github.com/ridi-oss/proxy-monster/pmon => ../pmon

// pmon depends on the in-repo mysqlwire; the replacement must be repeated here because a replace
// directive in a dependency's go.mod is ignored outside its own main module.
replace github.com/ridi-oss/proxy-monster/mysqlwire => ../mysqlwire
