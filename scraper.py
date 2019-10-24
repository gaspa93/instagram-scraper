from instagram import Instagram
from datetime import datetime, timedelta
from pymongo import MongoClient
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Instagram posts and user scraper.')
    parser.add_argument('--N', type=int, default=100, help='Number of posts to scrape')
    parser.add_argument('--u', type=str, help='Target username to scrape metadata')

    args = parser.parse_args()

    with Instagram(args.N) as scraper:
        with open(args.i, 'r') as urls_file:
            for url in urls_file:
                scraper.get_reviews(url)
