// Very small JSON-file database. Fine for a prototype / low-volume deployment.
// Swap for Postgres/SQLite later if you need real concurrency guarantees -
// concurrent writes to a JSON file are not safe under heavy load.
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const path = require("path");

const adapter = new FileSync(path.join(__dirname, "data.json"));
const db = low(adapter);

db.defaults({
  games: [
    { id: "wolf-st", title: "Wolf St: CPU Arena", type: "html", url: "about:blank", embeddable: null },
    { id: "nba2k13", title: "NBA 2K13 (PPSSPP)", type: "ppsspp", url: "http://localhost:8000/", embeddable: null }
  ],
  presence: {},        // wallet -> { gameId, gameTitle, since }
  faucetClaims: {},    // wallet -> lastClaimTimestampMs
  markets: [],          // prediction markets, see server.js for shape
  usedTxSignatures: {}, // signature -> true  (replay protection for on-chain stakes)
  sponsoredWallets: {}, // wallet -> { lockDays, bonusBps, penaltyBps, addedAt }
  vaultDeposits: []     // { id, wallet, amount, signature, depositedAt, unlockAt, bonusBps, penaltyBps, status, withdrawSignature }
}).write();

module.exports = db;
