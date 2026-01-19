# gqlmap

i got tired of piping output between three different unmaintained python scripts just to test a single endpoint, so i made this. it scans for vulnerabilities, figures out schemas even when introspection is off, and exports everything to tools you actually use.

## install

if you have rust:

```bash
cargo install --path .
```

## usage

### scanning

find potential vulnerabilities. if you don't know where the graphql endpoint is, add `--discover`.

```bash
# basic scan
gqlmap scan --target https://example.com/graphql

# find endpoints first, then scan
gqlmap scan --discover --target https://example.com

# send to burp
gqlmap scan -t https://example.com/graphql -x http://127.0.0.1:8080
```

### getting the schema

if introspection is enabled:

```bash
gqlmap introspect -t https://example.com/graphql -o schema.json
```

if they disabled introspection, use `infer` to bruteforce the fields. it uses a built-in wordlist or you can bring your own.

```bash
gqlmap infer -t https://example.com/graphql -o schema.json
```

### exporting

reading a 5mb json schema file is awful. turn it into a collection for bruno, postman, or just a massive bash script with curl commands.

```bash
# make a bruno collection
gqlmap export bruno --schema schema.json --url https://example.com/graphql --output ./bruno-collection

# make a shell script with every possible query
gqlmap export curl -s schema.json -u https://example.com/graphql -o attacks.sh
```

## license

mit. don't use this for illegal stuff, obviously.
