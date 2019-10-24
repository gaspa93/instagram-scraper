from instagram import Instagram
from datetime import datetime, timedelta
from pymongo import MongoClient
import argparse

DB_URL = 'mongodb://localhost:27017/'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Instagram posts and user scraper.')
    parser.add_argument('--N', type=int, default=100, help='Number of posts to scrape')
    parser.add_argument('--u', type=str, help='Target username')
    arser.add_argument('--t', type=str, help='Target hashtag to scrape posts')

    args = parser.parse_args()

    # default MongoDB connection
    client = MongoClient(DB_URL)
    # ig account credentials
    ig_credentials = json.load(open('credentials.json', 'r'))

    # get user metadata (no login needed) or also posts of target user
    if args.u:
        with Instagram(client, ig_credentials) as scraper:
            uid = scraper.get_account_by_username(args.u)

            # scraper.login()
            # user_id and username both needed
            # scraper.get_posts(args.u, uid, args.N)

    # get posts by hashtag
    elif args.t:
        with Instagram(client, ig_credentials) as scraper:
            scraper.login()
            scraper.get_posts_by_tag(args.t, args.N)