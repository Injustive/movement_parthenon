import os
from utils.run_config import ROOT_DIR


SLEEP_BETWEEN_WALLETS = 1, 300
SLEEP_BETWEEN_TASKS = 10, 30
SLEEP_FROM_TO = 600, 54000

CAPTCHA_API_KEY = 'CSK_26d3c750cb8a1bc4968a1fae4a636882c5f2e7940b663c8263af8f7f7a7a8074' # https://chromewebstore.google.com/detail/captcha-solver-automate-c/hlifkpholllijblknnmbfagnkjneagid

MANUAL_SOLVE_HCAPTCHA = False
CHAIN_LENGTH = 3
DONT_GO_NEXT_UNTIL_FULL_COMPLETE = True
MAX_SWAP_TIMES = 100 # 50 / 100 / 250 / 500
REMAIN_ON_WALLET_FOR_DAILY_TASKS = 3, 6

SIMULTANEOUS_TASKS = 3

# Do not edit!
HIDEN_RUN = False
DEFAULT_PASSWORD = 'CHANGE_tH1s_PASSWORD!'
BASE_EXTENSION_PATH = os.path.join(ROOT_DIR, 'run_movement_v2', 'data')
EXTENSION_RAZOR_WALLET = BASE_EXTENSION_PATH + '/razor_wallet/fdcnegogpncmfejlfnffnofpngdiejii/2.0.15_0'
EXTENSION_PATH_CAPTCHA_SOLVER = BASE_EXTENSION_PATH + '/captcha_solver/hlifkpholllijblknnmbfagnkjneagid/1.0.10_0'
EXTENTIONS_PATH = [EXTENSION_RAZOR_WALLET] + ([EXTENSION_PATH_CAPTCHA_SOLVER] if not MANUAL_SOLVE_HCAPTCHA else [])