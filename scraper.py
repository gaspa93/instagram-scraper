from instagram import Instagram
from datetime import datetime, timedelta
from pymongo import MongoClient
import argparse
import json

DB_URL = 'mongodb://localhost:27017/'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Instagram posts and user scraper.')
    parser.add_argument('--N', type=int, default=100, help='Number of posts to scrape')
    parser.add_argument('--u', type=str, default='mattia.gasparini.5', help='Target username')
    parser.add_argument('--t', type=str, help='Target hashtag to scrape posts')

    args = parser.parse_args()

    # default MongoDB connection
    client = MongoClient(DB_URL)

    # ig account credentials (needed for posts, not for users data)
    ig_credentials = json.load(open('credentials.json', 'r'))

    scraper = Instagram(ig_credentials)
    user = scraper.get_account_by_username(args.u)
    print(user)

    if scraper.login():
        posts = scraper.get_posts(user['username'], user['id'], first_req=True)

        n = len(posts)
        currposts = posts
        while n < args.N and currposts != []:
            currposts = scraper.get_posts(user['username'], user['id'])
            posts = posts + currposts
            n = len(posts)

        scraper.logout()
        
    else:
        print('Login failed!')
