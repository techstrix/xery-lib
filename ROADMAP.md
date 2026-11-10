# Roadmap

> `xery-lib` — a small, embeddable password vault library written in Rust.
> Vaults are protected with Argon2 password hashing, and stored secrets are encrypted at rest.

## Where things stand

- [x] Create, list, log in to, and log out of vaults
- [x] Add and read encrypted passwords
- [x] Password hashing with Argon2
- [ ] Full CRUD cycle
- [ ] Database agnosticism (SQLite only, for now)
- [ ] Comprehensive test coverage

## Planned work

### 1. Database agnosticism

Today the library is hard-wired to SQLite. The goal is to support multiple
backends without rewriting the vault logic.

- [ ] Abstract storage behind a trait
- [ ] Keep SQLite as the default, zero-config backend
- [ ] Add a second backend to prove the abstraction holds

### 2. Full CRUD cycle

Passwords can currently be created and read, but not updated or deleted.

- [ ] Update an existing password entry
- [ ] Delete a password entry
- [ ] Delete a vault
- [ ] Consistent error handling across all operations

### 3. Comprehensive tests

Existing tests cover the happy path only.

- [ ] Error cases (wrong password, duplicate names, missing entries)
- [ ] Round-trip encryption/decryption checks
- [ ] Multi-vault isolation
- [ ] Integration tests against a real (temporary) database file

## Contributing

Suggestions and pull requests are welcome. If you want to work on one of the
items above, open an issue first so we can keep the scope aligned.
