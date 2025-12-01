import os
import requests
import logging
import time
from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
    Bip39MnemonicValidator
)
from dotenv import load_dotenv
from termcolor import colored

# Load environment variables
load_dotenv()
logging.basicConfig(filename='wallet_checker.log', level=logging.INFO)

# API keys and endpoints
COVALENT_API_KEY = os.getenv('COVALENT_API_KEY')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

# Chain IDs
CHAIN_IDS = {
    "Ethereum": 1,
    "BSC": 56,
    "Polygon": 137,
    "Bitcoin": "btc-mainnet"
}

# USDT contracts
USDT_ETH_CONTRACT = os.getenv('USDT_ETH_CONTRACT', '').lower()
USDT_BSC_CONTRACT = os.getenv('USDT_BSC_CONTRACT', '').lower()
USDT_POLYGON_CONTRACT = os.getenv('USDT_POLYGON_CONTRACT', '').lower()

session = requests.Session()

def send_telegram_message(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("⚠️ Telegram credentials missing.")
        return
    url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
    payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'Markdown'}
    try:
        response = session.post(url, data=payload)
        if response.status_code != 200:
            print(f"❌ Telegram error: {response.text}")
    except Exception as e:
        print(f"❌ Telegram exception: {e}")

def safe_request(url, params=None):
    for attempt in range(5):
        response = session.get(url, auth=(COVALENT_API_KEY, ""), params=params)
        if response.status_code == 429:
            wait = 2 ** attempt
            logging.warning(f"Rate limit hit. Retrying in {wait}s...")
            time.sleep(wait)
        else:
            return response
    return None

def is_valid_mnemonic(mnemonic):
    return Bip39MnemonicValidator().IsValid(mnemonic)

def derive_address(seed_bytes, coin_type):
    bip44 = Bip44.FromSeed(seed_bytes, coin_type)
    return bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

def check_covalent_balance(address, chain_id):
    url = f"https://api.covalenthq.com/v1/{chain_id}/address/{address}/balances_v2/"
    response = safe_request(url)
    if response and response.status_code == 200:
        data = response.json()
        items = data.get("data", {}).get("items", [])
        native_balance = 0
        token_balances = {}
        for item in items:
            contract = item.get("contract_address", "").lower()
            balance = int(item.get("balance", 0))
            decimals = int(item.get("contract_decimals", 18))
            symbol = item.get("contract_ticker_symbol", "")
            value = balance / (10 ** decimals)
            if contract == "":
                native_balance = value
            token_balances[contract] = (symbol, value)
        return native_balance, token_balances
    return 0, {}

def check_btc_balance(mnemonic):
    seed = Bip39SeedGenerator(mnemonic).Generate()
    addr_obj = derive_address(seed, Bip44Coins.BITCOIN)
    address = addr_obj.PublicKey().ToAddress()
    url = f"https://api.covalenthq.com/v1/{CHAIN_IDS['Bitcoin']}/address/{address}/balances_v2/"
    response = safe_request(url)
    if response and response.status_code == 200:
        data = response.json()
        items = data.get("data", {}).get("items", [])
        balance = sum(int(item.get("balance", 0)) for item in items) / 1e8
        return address, balance
    return address, 0

def process_mnemonic(mnemonic):
    mnemonic = mnemonic.strip()
    if not is_valid_mnemonic(mnemonic):
        logging.warning(f'Invalid mnemonic: {mnemonic}')
        return

    try:
        seed = Bip39SeedGenerator(mnemonic).Generate()
        evm_results = []
        has_balance = False

        # Ethereum
        eth_addr = derive_address(seed, Bip44Coins.ETHEREUM).PublicKey().ToAddress()
        eth_bal, eth_tokens = check_covalent_balance(eth_addr, CHAIN_IDS["Ethereum"])
        eth_usdt = eth_tokens.get(USDT_ETH_CONTRACT, ("USDT", 0))[1]
        evm_results.append(("Ethereum", eth_addr, eth_bal, eth_usdt))
        if eth_bal > 0 or eth_usdt > 0:
            has_balance = True

        # BSC
        bsc_addr = derive_address(seed, Bip44Coins.ETHEREUM).PublicKey().ToAddress()
        bsc_bal, bsc_tokens = check_covalent_balance(bsc_addr, CHAIN_IDS["BSC"])
        bsc_usdt = bsc_tokens.get(USDT_BSC_CONTRACT, ("USDT", 0))[1]
        evm_results.append(("BSC", bsc_addr, bsc_bal, bsc_usdt))
        if bsc_bal > 0 or bsc_usdt > 0:
            has_balance = True

        # Polygon
        polygon_addr = derive_address(seed, Bip44Coins.ETHEREUM).PublicKey().ToAddress()
        polygon_bal, polygon_tokens = check_covalent_balance(polygon_addr, CHAIN_IDS["Polygon"])
        polygon_usdt = polygon_tokens.get(USDT_POLYGON_CONTRACT, ("USDT", 0))[1]
        evm_results.append(("Polygon", polygon_addr, polygon_bal, polygon_usdt))
        if polygon_bal > 0 or polygon_usdt > 0:
            has_balance = True

        # BTC
        btc_addr, btc_bal = check_btc_balance(mnemonic)
        if btc_bal > 0:
            has_balance = True

        if has_balance:
            message = f"🔐 *Mnemonic:* `{mnemonic}`\n"
            for name, addr, native_bal, usdt_bal in evm_results:
                message += f"🟣 *{name}*: `{addr}` — {native_bal:.6f} {name.upper()}\n"
                if usdt_bal > 0:
                    message += f"💵 USDT ({name}): {usdt_bal:.2f} USDT\n"
            message += f"🟠 *BTC*: `{btc_addr}` — {btc_bal:.8f} BTC"
            send_telegram_message(message)
            print(colored("💰 Active Wallet Found!", "green", attrs=["bold"]))
            print(message)
        else:
            print(colored(f"Empty Wallet: {mnemonic}", "red"))
    except Exception as e:
        logging.error(f'Error: {e}')

def main(mnemonic_file):
    log_file = f"checked_{mnemonic_file}"
    while True:
        with open(mnemonic_file, 'r') as f:
            mnemonics = [line.strip() for line in f if line.strip()]

        if not mnemonics:
            print(colored("✅ All mnemonics checked.", "cyan"))
            send_telegram_message(f"✅ Finished checking all mnemonics in `{mnemonic_file}`.")
            break

        current = mnemonics[0]
        process_mnemonic(current)

        # Log the checked mnemonic
        with open(log_file, 'a') as log:
            log.write(current + "\n")

        # Rewrite the file without the checked mnemonic
        with open(mnemonic_file, 'w') as f:
            for m in mnemonics[1:]:
                f.write(m + "\n")

        time.sleep(1)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python wallet_checker.py mnemonics_1.txt")
    else:
        main(sys.argv[1])