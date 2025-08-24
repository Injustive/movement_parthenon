import os
from utils.run_config import ROOT_DIR


SLEEP_BETWEEN_WALLETS = 1, 100
SLEEP_BETWEEN_TASKS = 10, 30
SLEEP_FROM_TO = 600, 54000

CAPTCHA_API_KEY = '' # https://chromewebstore.google.com/detail/captcha-solver-automate-c/hlifkpholllijblknnmbfagnkjneagid

MANUAL_SOLVE_HCAPTCHA = True
CHAIN_LENGTH = 1
DONT_GO_NEXT_UNTIL_FULL_COMPLETE = True
MAX_SWAP_TIMES = 500 # 50 / 100 / 250 / 500
REMAIN_ON_WALLET_FOR_DAILY_TASKS = 5, 10

SIMULTANEOUS_TASKS = 3

# Do not edit!
HIDEN_RUN = False
DEFAULT_PASSWORD = 'CHANGE_tH1s_PASSWORD!'
BASE_EXTENSION_PATH = os.path.join(ROOT_DIR, 'run_movement_v2', 'data')
EXTENSION_RAZOR_WALLET = BASE_EXTENSION_PATH + '/razor_wallet/fdcnegogpncmfejlfnffnofpngdiejii/2.0.15_0'
EXTENSION_PATH_CAPTCHA_SOLVER = BASE_EXTENSION_PATH + '/captcha_solver/hlifkpholllijblknnmbfagnkjneagid/1.0.10_0'
EXTENTIONS_PATH = [EXTENSION_RAZOR_WALLET] + ([EXTENSION_PATH_CAPTCHA_SOLVER] if not MANUAL_SOLVE_HCAPTCHA else [])
