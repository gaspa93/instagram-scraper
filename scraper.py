from instagram import Instagram
from datetime import datetime, timedelta
from pymongo import MongoClient
import argparse
import json
import requests

DB_URL = 'mongodb://localhost:27017/'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Instagram posts and user scraper.')
    parser.add_argument('--N', type=int, default=100, help='Number of posts to scrape')
    parser.add_argument('--u', type=str, default='mattia.gasparini.5', help='Target username')
    parser.add_argument('--t', type=str, help='Target hashtag to scrape posts')

    args = parser.parse_args()

    # default MongoDB connection
    client = MongoClient(DB_URL)

    # ig account credentials and session object (needed for get_posts method)
    ig_credentials = json.load(open('credentials.json', 'r'))
    session = requests.Session()

    if args.u:
        # get user metadata (no login needed)
        with Instagram(client) as scraper:
            uid = scraper.get_account_by_username(args.u)
            print(uid)

        # get posts information with login
        # user_id and username both needed: get id with previous method or provide both manually
        with Instagram(client, cred=ig_credentials, s=session) as scraper:
            scraper.login()

            if scraper.logged_in:
                scraper.get_posts(args.u, uid, args.N)

    # get posts by hashtag
    elif args.t:
        with Instagram(client, ig_credentials, s=Session) as scraper:
            scraper.login()
            scraper.get_posts_by_tag(args.t, args.N)
