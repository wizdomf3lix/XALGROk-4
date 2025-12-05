import os
import time
import logging
import threading
import requests
from typing import List, Dict, Tuple
from dotenv import load_dotenv
from termcolor import colored
from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip39MnemonicValidator
)

# ---------------------------
# Setup & configuration
# ---------------------------
load_dotenv()
logging.basicConfig(filename='wallet_checker.log', level=logging.INFO)

BITQUERY_API_KEY = os.getenv('BITQUERY_API_KEY', '')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '')

USDT_ETH_CONTRACT = os.getenv('USDT_ETH_CONTRACT', '').lower()
USDT_BSC_CONTRACT = os.getenv('USDT_BSC_CONTRACT', '').lower()
USDT_POLYGON_CONTRACT = os.getenv('USDT_POLYGON_CONTRACT', '').lower()

# Tuned for free Railway + Bitquery free tier
BATCH_SIZE = 50                 # mnemonics per batch
REQUESTS_PER_SEC = 2.0          # cap QPS per instance
MAX_BACKOFF_SECONDS = 30        # max exponential backoff
THREADS_PER_BATCH = 4           # keep low to conserve CPU

BITQUERY_URL = "https://graphql.bitquery.io"
session = requests.Session()
session.headers.update({"X-API-KEY": BITQUERY_API_KEY})

# ---------------------------
# Utilities
# ---------------------------
class RateLimiter:
    """Simple token-bucket rate limiter."""
    def __init__(self, rate_per_sec: float):
        self.tokens = rate_per_sec
        self.rate = rate_per_sec
        self.last = time.time()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.time()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            if self.tokens < 1.0:
                sleep_time = (1.0 - self.tokens) / self.rate
                time.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1.0

rate_limiter = RateLimiter(REQUESTS_PER_SEC)

def safe_post(url: str, payload: dict, headers: dict = None, retries: int = 5):
    """POST with rate limit + exponential backoff on 429/5xx."""
    attempt = 0
    while attempt < retries:
        rate_limiter.acquire()
        try:
            resp = session.post(url, json=payload, headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp
            if resp.status_code in (429, 500, 502, 503, 504):
                wait = min(MAX_BACKOFF_SECONDS, 2 ** attempt)
                logging.warning(f"HTTP {resp.status_code}. Backing off {wait}s...")
                time.sleep(wait)
                attempt += 1
                continue
            logging.error(f"POST error {resp.status_code}: {resp.text}")
            return resp
        except Exception as e:
            wait = min(MAX_BACKOFF_SECONDS, 2 ** attempt)
            logging.error(f"POST exception: {e}. Retrying in {wait}s")
            time.sleep(wait)
            attempt += 1
    return None

def send_telegram(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("⚠️ Telegram credentials missing.")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try:
        resp = requests.post(url, data=data, timeout=15)
        if resp.status_code != 200:
            logging.error(f"Telegram error: {resp.text}")
    except Exception as e:
        logging.error(f"Telegram exception: {e}")

def is_valid_mnemonic(m: str) -> bool:
    try:
        return Bip39MnemonicValidator().IsValid(m.strip())
    except Exception:
        return False

def derive_evm_address(seed_bytes) -> str:
    """Derive first external address on ETH path (used for ETH/BSC/Polygon)."""
    node = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM).Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    return node.PublicKey().ToAddress()

def derive_btc_address(seed_bytes) -> str:
    node = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN).Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    return node.PublicKey().ToAddress()

# ---------------------------
# Bitquery GraphQL
# ---------------------------
def gql_evm_balances_batch(addresses: List[str], network: str) -> Dict[str, Dict]:
    """
    Query balances for multiple addresses on an EVM network.
    Returns {address: {"native": float, "tokens": {contract: (symbol, value)}}}
    """
    query = f"""
    query ($addresses: [String!]) {{
      {network}(network: {network}) {{
        addresses(address: {{in: $addresses}}) {{
          address
          balances {{
            currency {{ symbol address }}
            value
          }}
        }}
      }}
    }}
    """
    variables = {"addresses": addresses}
    resp = safe_post(BITQUERY_URL, {"query": query, "variables": variables})
    out: Dict[str, Dict] = {addr: {"native": 0.0, "tokens": {}} for addr in addresses}
    if not resp:
        return out
    try:
        data = resp.json().get("data", {}).get(network, {}).get("addresses", [])
        for entry in data:
            addr = entry.get("address")
            native = 0.0
            tokens = {}
            for b in entry.get("balances", []):
                caddr = (b.get("currency", {}).get("address") or "").lower()
                sym = b.get("currency", {}).get("symbol") or ""
                val = float(b.get("value") or 0)
                if caddr == "" or caddr is None:
                    native = val
                else:
                    tokens[caddr] = (sym, val)
            out[addr] = {"native": native, "tokens": tokens}
    except Exception as e:
        logging.error(f"Parse error EVM balances: {e}")
    return out

def gql_btc_balances_batch(addresses: List[str]) -> Dict[str, float]:
    """
    Query BTC balances for multiple addresses.
    Returns {address: btc_balance_btc}
    """
    query = """
    query ($addresses: [String!]) {
      bitcoin {
        addresses(address: {in: $addresses}) {
          address
          balance
        }
      }
    }
    """
    variables = {"addresses": addresses}
    resp = safe_post(BITQUERY_URL, {"query": query, "variables": variables})
    out = {addr: 0.0 for addr in addresses}
    if not resp:
        return out
    try:
        data = resp.json().get("data", {}).get("bitcoin", {}).get("addresses", [])
        for entry in data:
            addr = entry.get("address")
            sat = int(entry.get("balance") or 0)
            out[addr] = sat / 1e8
    except Exception as e:
        logging.error(f"Parse error BTC balances: {e}")
    return out

# ---------------------------
# Processing logic
# ---------------------------
def check_batch(mnemonics: List[str]) -> List[Tuple[str, Dict]]:
    """
    Derive addresses for mnemonics and fetch balances in batches.
    Returns list of (mnemonic, result_dict) where result_dict includes chain balances.
    """
    seeds = []
    for m in mnemonics:
        m = m.strip()
        if not is_valid_mnemonic(m):
            logging.warning(f"Invalid mnemonic skipped: {m}")
            seeds.append(None)
            continue
        try:
            seeds.append(Bip39SeedGenerator(m).Generate())
        except Exception as e:
            logging.error(f"Seed gen error: {e}")
            seeds.append(None)

    # Derive addresses
    evm_addrs, btc_addrs = [], []
    addr_map_evm = {}   # index -> evm address
    addr_map_btc = {}   # index -> btc address
    for i, seed in enumerate(seeds):
        if seed is None:
            addr_map_evm[i] = None
            addr_map_btc[i] = None
            continue
        try:
            a_evm = derive_evm_address(seed)
            a_btc = derive_btc_address(seed)
        except Exception as e:
            logging.error(f"Derivation error: {e}")
            a_evm, a_btc = None, None
        addr_map_evm[i] = a_evm
        addr_map_btc[i] = a_btc
        if a_evm:
            evm_addrs.append(a_evm)
        if a_btc:
            btc_addrs.append(a_btc)

    # Query EVM networks in batches
    eth = gql_evm_balances_batch(evm_addrs, "ethereum")
    bsc = gql_evm_balances_batch(evm_addrs, "bsc")
    polygon = gql_evm_balances_batch(evm_addrs, "polygon")

    # BTC balances
    btc = gql_btc_balances_batch(btc_addrs)

    # Collect results
    results = []
    for i, m in enumerate(mnemonics):
        a_evm = addr_map_evm.get(i)
        a_btc = addr_map_btc.get(i)
        item = {
            "mnemonic": m.strip(),
            "eth": {"addr": a_evm, "native": 0.0, "usdt": 0.0},
            "bsc": {"addr": a_evm, "native": 0.0, "usdt": 0.0},
            "polygon": {"addr": a_evm, "native": 0.0, "usdt": 0.0},
            "btc": {"addr": a_btc, "native": 0.0},
        }
        if a_evm:
            e = eth.get(a_evm, {"native": 0.0, "tokens": {}})
            b = bsc.get(a_evm, {"native": 0.0, "tokens": {}})
            p = polygon.get(a_evm, {"native": 0.0, "tokens": {}})
            item["eth"]["native"] = e.get("native", 0.0)
            item["bsc"]["native"] = b.get("native", 0.0)
            item["polygon"]["native"] = p.get("native", 0.0)
            item["eth"]["usdt"] = e.get("tokens", {}).get(USDT_ETH_CONTRACT, ("USDT", 0.0))[1] if USDT_ETH_CONTRACT else 0.0
            item["bsc"]["usdt"] = b.get("tokens", {}).get(USDT_BSC_CONTRACT, ("USDT", 0.0))[1] if USDT_BSC_CONTRACT else 0.0
            item["polygon"]["usdt"] = p.get("tokens", {}).get(USDT_POLYGON_CONTRACT, ("USDT", 0.0))[1] if USDT_POLYGON_CONTRACT else 0.0
        if a_btc:
            item["btc"]["native"] = btc.get(a_btc, 0.0)
        results.append((m.strip(), item))
    return results

def alert_if_active(item: Dict):
    has_balance = (
        (item["eth"]["native"] > 0) or (item["eth"]["usdt"] > 0) or
        (item["bsc"]["native"] > 0) or (item["bsc"]["usdt"] > 0) or
        (item["polygon"]["native"] > 0) or (item["polygon"]["usdt"] > 0) or
        (item["btc"]["native"] > 0)
    )
    if not has_balance:
        return False

    lines = [f"🔐 *Mnemonic:* `{item['mnemonic']}`"]
    if item["eth"]["addr"]:
        lines.append(f"🟣 Ethereum: `{item['eth']['addr']}` — {item['eth']['native']:.6f} ETH")
        if item["eth"]["usdt"] > 0:
            lines.append(f"💵 USDT (Ethereum): {item['eth']['usdt']:.2f} USDT")
    if item["bsc"]["addr"]:
        lines.append(f"🟣 BSC: `{item['bsc']['addr']}` — {item['bsc']['native']:.6f} BNB")
        if item["bsc"]["usdt"] > 0:
            lines.append(f"💵 USDT (BSC): {item['bsc']['usdt']:.2f} USDT")
    if item["polygon"]["addr"]:
        lines.append(f"🟣 Polygon: `{item['polygon']['addr']}` — {item['polygon']['native']:.6f} MATIC")
        if item["polygon"]["usdt"] > 0:
            lines.append(f"💵 USDT (Polygon): {item['polygon']['usdt']:.2f} USDT")
    if item["btc"]["addr"]:
        lines.append(f"🟠 BTC: `{item['btc']['addr']}` — {item['btc']['native']:.8f} BTC")
    send_telegram("\n".join(lines))
    print(colored("💰 Active Wallet Found!", "green", attrs=["bold"]))
    print("\n".join(lines))
    return True

# ---------------------------
# File loop (delete as you go)
# ---------------------------
def read_chunk(file_path: str, n: int) -> List[str]:
    """Read up to n mnemonics from file."""
    mnemonics = []
    with open(file_path, "r") as f:
        for _ in range(n):
            line = f.readline()
            if not line:
                break
            line = line.strip()
            if line:
                mnemonics.append(line)
    return mnemonics

def trim_file_head(file_path: str, count: int):
    """Remove first 'count' lines from file efficiently."""
    with open(file_path, "r") as f:
        lines = f.readlines()
    with open(file_path, "w") as f:
        f.writelines(lines[count:])

def main(mnemonic_file: str):
    checked_log = f"checked_{os.path.basename(mnemonic_file)}"
    batch_index = 0

    while True:
        chunk = read_chunk(mnemonic_file, BATCH_SIZE)
        if not chunk:
            print(colored("✅ All mnemonics checked.", "cyan"))
            send_telegram(f"✅ Finished checking all mnemonics in `{mnemonic_file}`.")
            break

        batch_index += 1
        print(colored(f"Processing batch #{batch_index} ({len(chunk)} mnemonics)...", "blue"))

        results = check_batch(chunk)

        # Alerts + logging
        hits = 0
        with open(checked_log, "a") as logf:
            for m, item in results:
                if alert_if_active(item):
                    hits += 1
                logf.write(m + "\n")

        # Delete processed mnemonics from file
        trim_file_head(mnemonic_file, len(chunk))

        # Progress message
        print(colored(f"Batch #{batch_index} done. Hits: {hits}.", "cyan"))

        # Gentle throttle between batches to avoid spikes
        time.sleep(0.5)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python wallet_checker.py mnemonics_1.txt")
    else:
        main(sys.argv[1])