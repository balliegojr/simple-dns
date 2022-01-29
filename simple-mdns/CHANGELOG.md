# Simple MDNS
## 0.3.6
- Update dependencies

## 0.3.5
- Update dependencies

## 0.3.4
- Add TXT records to service queries

## 0.3

- Increase simple-dns version
- Add attributes information (TXT records) and instance name to service discovery
- Changes resource manager internal structure to a Trie
- Replaces specific functions to add information to service discovery in flavor of a more generic one


## 0.2.2

Increase simple-dns version

## 0.2.1

Fix a bug that caused the refresh on the service discovery to panic
Increase socket2 version number

## 0.2.0

Remove Futures and Tokio dependencies by switching to a simple thread implementation

## 0.1.0

Initial project release

Add oneshot resolver, simple responder and service discovery implementations
