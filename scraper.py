from instagram import Instagram
from datetime import datetime, timedelta
import argparse
import json

DB_URL = 'mongodb://localhost:27017/'

def get_user_posts(scraper, u, max_posts):

    user = scraper.get_account_by_username(u)
    if scraper.login():
        posts = scraper.get_posts(user['username'], user['id'], first_req=True)

        n = len(posts)
        currposts = posts
        while n < max_posts and currposts != []:
            currposts = scraper.get_posts(user['username'], user['id'])
            posts = posts + currposts
            n = len(posts)

        scraper.logout()

        return 0
    else:
        return 1


def get_hashtag_posts(scraper, t, max_posts):

    if scraper.login():
        posts = scraper.get_posts_by_tag(t, first_req=True)

        n = len(posts)
        currposts = posts
        while n < max_posts and currposts != []:
            currposts = scraper.get_posts(user['username'], user['id'])
            posts = posts + currposts
            n = len(posts)

        scraper.logout()

        return 0
    else:
        return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Instagram posts and user scraper.')
    parser.add_argument('--N', type=int, default=100, help='Number of posts to scrape')
    parser.add_argument('--u', type=str, default='mattia.gasparini.5', help='Target username')
    parser.add_argument('--t', type=str, help='Target hashtag to scrape posts')

    args = parser.parse_args()

    # ig account credentials (needed for posts, not for users data)
    ig_credentials = json.load(open('credentials.json', 'r'))
    scraper = Instagram(ig_credentials)

    if not args.t:
        get_user_posts(scraper, args.u, args.N)
    else:
        get_hashtag_posts(scraper, args.t, args.N)
