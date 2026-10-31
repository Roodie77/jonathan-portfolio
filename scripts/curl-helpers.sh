# Helpers for testing the Roodie APIs with curl.
#
#   source scripts/curl-helpers.sh
#
# Works in bash and zsh (macOS, Linux, Git Bash or WSL on Windows). Needs curl and Node 18+.
# Every helper is a thin wrapper, so you can always replace `api` with plain `curl` to see the raw output.

# Where the local server is listening (see: node server.js)
export HOST="${HOST:-http://localhost:3000}"
export INS="$HOST/insuretech/v1"   # Roodie Insuretech API
export SHD="$HOST/shield/v1"       # Xeno Shield API

# Demo credentials
export CLAIMANT="Authorization: Bearer claimant_demo_key"   # Insuretech: file, edit, appeal, withdraw
export ADJUSTER="Authorization: Bearer adjuster_demo_key"   # Insuretech: decide, pay, restore, policies
export SHIELD_KEY="Authorization: Bearer xeno_demo_key"     # Shield: all writes

# Content types
export JSON="Content-Type: application/json"
export MERGE="Content-Type: application/merge-patch+json"

# api: curl that prints the HTTP status first, then the JSON body pretty-printed.
#   api $INS/policies
#   api -X POST $INS/claims -H "$CLAIMANT" -H "$JSON" -d '{...}'
api() {
  local out code body
  out=$(curl -s -w $'\n%{http_code}' "$@") || return $?
  code=${out##*$'\n'}
  body=${out%$'\n'*}
  echo "HTTP $code"
  if [ -n "$body" ]; then
    printf '%s' "$body" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{console.log(JSON.stringify(JSON.parse(s),null,2))}catch(e){console.log(s)}})"
  fi
}

# field: pull a value out of JSON on stdin. Give it a path (.claims.total) or any JavaScript
# expression over the parsed JSON, which is available as `d`.
#   curl -s $INS/stats | field .claims.total
#   curl -s $INS/stats | field 'd.claims.total + " claims"'
field() {
  node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));const e=process.argv[1];const v=/^[.[]/.test(e)?eval('d'+e):eval(e);console.log(v!==null&&typeof v==='object'?JSON.stringify(v):v)" "$1"
}

# etag: print the current ETag of a URL (needed for If-Match on writes).
#   ETAG=$(etag $INS/claims/$ID)
etag() { curl -sI "$1" | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}'; }

# day: a calendar date N days from today (incident dates must be real and recent).
#   day -3   ->  three days ago
day() { node -pe "new Date(Date.now()+($1)*864e5).toISOString().slice(0,10)"; }

# reset_demo: put both APIs back to their seed data.
reset_demo() {
  curl -s -o /dev/null -w "insuretech reset: HTTP %{http_code}\n" -X POST "$INS/sandbox/reset" -H "$ADJUSTER"
  curl -s -o /dev/null -w "shield reset:     HTTP %{http_code}\n" -X POST "$SHD/sandbox/reset" -H "$SHIELD_KEY"
}

echo "Roodie API helpers loaded. Insuretech: $INS   Shield: $SHD"
