from dateutil.relativedelta import relativedelta
import time
import json
import re
import requests
from datetime import date, timedelta, datetime
import logging
import traceback

# constants
STORIES_UA = 'Instagram 9.5.2 (iPhone7,2; iPhone OS 9_3_3; en_US; en-US; scale=2.00; 750x1334) AppleWebKit/420+'
BASE_URL = 'https://www.instagram.com/'
BASE_LOGIN_URL = BASE_URL + 'accounts/login/'
LOGIN_URL = BASE_LOGIN_URL + 'ajax/'
LOGOUT_URL = BASE_URL + 'accounts/logout/'
CHROME_WIN_UA = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
USER_URL = BASE_URL + '{0}/?__a=1'
USER_INFO = 'https://i.instagram.com/api/v1/users/{}/info/'
queryIdPosts = '17880160963012870'
QUERY_HASH = '1780c1b186e2c37de9f7da95ce41bb67'
N_POSTS = 50  #  number of posts per query

class Instagram:

    def __init__(self, db_client, cred, s=None):
        self.db = db_client
        self.login_ = cred
        self.logger = self.__get_logger()
        self.session = s

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        if exc_type is not None:
            traceback.print_exception(exc_type, exc_value, tb)

        self.db.close()
        self.logout()

        return True

    def __get_logger(self):
        # create logger
        logger = logging.getLogger('instagram-scraper')
        logger.setLevel(logging.DEBUG)

        # create console handler and set level to debug
        fh = logging.FileHandler('ig-scraper.log')
        fh.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # add formatter to ch
        fh.setFormatter(formatter)

        # add ch to logger
        logger.addHandler(fh)

        return logger

    def login(self):
        """Logs in to instagram."""
        self.session.headers.update({'Referer': BASE_URL})
        req = self.session.get(BASE_URL)

        if 'csrftoken' in req.cookies:
            self.session.headers.update({'X-CSRFToken': req.cookies['csrftoken']})
        else:
            shared_data = self.__get_shared_data(self.login_['username'])
            self.session.headers.update(
                {'X-CSRFToken': shared_data['config']['csrf_token'],
                 'X-Instagram-AJAX': shared_data['rollout_hash'],
                 'X-Requested-With': 'XMLHttpRequest'})

        login_data = {'username': self.login_['username'], 'password': self.login_['password']}
        login = self.session.post(LOGIN_URL, data=login_data, allow_redirects=True)
        if 'csrftoken' in login.cookies:
            self.session.headers.update({'X-CSRFToken': login.cookies['csrftoken']})
        cookies = login.cookies

        # if 'sessionid' in login.cookies:
        #    sessionid = login.cookies['sessionid']

        login_text = json.loads(login.text)

        if login_text.get('authenticated') and login.status_code == 200:
            self.cookies = cookies
        else:
            self.logger.error('Login failed for ' + self.login_['username'])

            if 'checkpoint_url' in login_text:
                checkpoint_url = login_text.get('checkpoint_url')
                self.logger.warn('Please verify your account at ' + BASE_URL[0:-1] + checkpoint_url)
                self.__login_challenge(checkpoint_url)

            elif 'errors' in login_text:
                for count, error in enumerate(login_text['errors'].get('error')):
                    count += 1
                    self.logger.error('Session error %(count)s: "%(error)s"' % locals())
            else:
                self.logger.error('Look at login file')

    def logout(self):
        """Logs out of instagram."""
        try:
            logout_data = {'csrfmiddlewaretoken': self.cookies['csrftoken']}
            self.session.post(LOGOUT_URL, data=logout_data)

            self.logger.info('Log out successfull.')

        except requests.exceptions.RequestException:
            self.logger.warn('Failed to log out.')

    def get_account_by_id(self, id_user):

        url = USER_INFO.format(id_user)
        page = self.__send_request(url)

        try:
            dataUser = json.loads(page.text)['user']
            dataUser['id_user'] = id_user

            self.db['igUser'].insert_one(dataUser)

            return 0
        except:
            try:
                error_resp = json.loads(page.text)
                self.logger.error(error_resp)

                return error_resp

            except Exception as e:
                self.logger.error(str(e))

            return 1

    def get_account_by_username(self, instagram_profile):

        url = 'https://www.instagram.com/' + instagram_profile

        try:
            page = self.__send_request(url)
            json_data = re.findall(r'window._sharedData = (.*?);</script>', page.text)
            data = json.loads(json_data[0])

            u = data['entry_data']['ProfilePage'][0]['graphql']['user']

            self.db['user'].insert_one(u)

            return u['id']

        except:
            try:
                error_resp = json.loads(page.text)
                self.logger.error(error_resp)

                return error_resp

            except Exception as e:
                self.logger.error(str(e))

            return None

    def __query_ig(self, params, headers, cookies, qtype='user'):
        posts_query = self.__send_request('https://www.instagram.com/graphql/query/', params=params, headers=headers, cookies=cookies)

        posts_data = json.loads(posts_query.content)

        if qtype == 'user':
            edgepar = 'edge_owner_to_timeline_media'
        elif qtype == 'hashtag':
            edgepar = 'edge_hashtag_to_media'

        more_pages = posts_data['data'][qtype][edgepar]['page_info']['has_next_page']
        end_cursor = posts_data['data'][qtype][edgepar]['page_info']['end_cursor']
        posts = posts_data['data'][qtype][edgepar]['edges']

        return posts, more_pages, end_cursor


    def __get_post_data(self, posts, n_to_scrape):

        n_collected = 0
        for item in posts:

            id_post = bson.int64.Int64(item['node']['id'])
            last_post_collected_timestamp = item['node']['taken_at_timestamp']
            if n_collected < n_to_scrape:
                item_posts = {}
                item_posts['id_post'] = id_post

                if item['node']['edge_media_to_caption']['edges']:
                    item_posts['caption'] = filterString(item['node']['edge_media_to_caption']['edges'][0]['node']['text'])
                else:
                    item_posts['caption'] = ""
                item_posts['shortcode'] = item['node']['shortcode']
                item_posts['link_post'] = "https://www.instagram.com/p/" + item['node']['shortcode']
                item_posts['timestamp'] = datetime.fromtimestamp(int(item['node']['taken_at_timestamp']))
                item_posts['date'] = str(item_posts['timestamp'])
                item_posts['img_url'] = item['node']['display_url']
                item_posts['id_user'] = bson.int64.Int64(item['node']['owner']['id'])
                item_posts['comments'] = item['node']['edge_media_to_comment']['count']
                item_posts['likes'] = item['node']['edge_liked_by']['count']
                item_posts['is_video'] = item['node']['is_video']
                if item['node']['is_video']:
                    item_posts['video_count'] = item['node']['video_view_count']
                else:
                    item_posts['video_count'] = 0

                item_posts['username'] = instagram_profile

                try:
                    self.db['post'].insert_one(item_posts)
                    n_collected += 1
                except Exception as e:
                    self.logger.warn('MongoDB Error: ' + type(e).__name__)

            else:
                self.logger.info('Posts collected: {}'.format(Nposts))

        return n_collected

    # need both username and user_id to obtain the posts
    def get_posts(self, instagram_profile, user_id, n):

        cookies = {
            'rur': 'FRC',
            'csrftoken': self.cookies['csrftoken'],
            'mid': 'WdD8XwAEAAHvcAob7guc69duJXcG',
            'ds_user_id': self.cookies['ds_user_id'],
            'sessionid': self.cookies['sessionid']
        }

        headers = {
            'Host': 'www.instagram.com',
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:56.0) Gecko/20100101 Firefox/56.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'X-Requested-With': 'XMLHttpRequest',
            'DNT': '1',
            'Connection': 'keep-alive',
        }

        # First Query
        params = (
            ('query_id', str(queryIdPosts)),
            ('variables', '{"id":"' + str(user_id) + '","first":' + str(N_POSTS) + '}'),
        )

        posts, more_pages, end_cursor= self.__query_ig(params, headers, cookies)
        n_collected = self.__get_post_data(posts, n)

        # Iterate until finish
        while more_pages and n_collected < n:

            params = (

                ('query_id', str(queryIdPosts)),
                ('variables',
                 '{"id":"' + str(user_id) + '","first":' + str(N_POSTS) + ',"after":"' + str(end_cursor) + '" }')
            )

            posts, more_pages, end_cursor= self.__query_ig(params, headers, cookies)

            # collect the delta between target number and what we have already collected
            n = n - n_collected
            n_collected = self.__get_post_data(posts, n)

            # wait before next request
            time.sleep(3)

        return 0

    # get posts containing a specific hashtag
    def get_posts_by_tag(self, instagram_tag, n):

        cookies = {
            'rur': 'FRC',
            'csrftoken': self.cookies['csrftoken'],
            'mid': 'WdD8XwAEAAHvcAob7guc69duJXcG',
            'ds_user_id': self.cookies['ds_user_id'],
            'sessionid': self.cookies['sessionid']
        }

        headers = {
            'Host': 'www.instagram.com',
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:56.0) Gecko/20100101 Firefox/56.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'X-Requested-With': 'XMLHttpRequest',
            'DNT': '1',
            'Connection': 'keep-alive',
        }

        # First Query
        params = (
            ('query_hash', QUERY_HASH),
            ('variables', '{"tag_name":"' + instagram_tag + '","first":' + str(N_POSTS) + '}')
        )

        posts, more_pages, end_cursor= self.__query_ig(params, headers, cookies)
        n_collected = self.__get_post_data(posts, n)

        while more_pages and n_collected < n:

            params = (

                ('query_hash', QUERY_HASH),
                ('variables',
                 '{"tag_name":"' + instagram_tag + '","first":' + str(N_POSTS) + ',"after":"' + str(
                     end_cursor) + '" }')
            )

            posts, more_pages, end_cursor= self.__query_ig(params, headers, cookies, qtype='hashtag')

            # collect the delta between target number and what we have already collected
            n = n - n_collected
            n_collected = self.__get_post_data(posts, n)

            time.sleep(3)

        return 0

    def __get_shared_data(self, username):
        """Fetches the user's metadata."""
        resp = self.session.get(BASE_URL + username).text

        if resp is not None and '_sharedData' in resp:
            try:
                shared_data = resp.split("window._sharedData = ")[1].split(";</script>")[0]
                return json.loads(shared_data)
            except (TypeError, KeyError, IndexError):
                pass

    ## function to handle login challenge ##
    def __login_challenge(self, checkpoint_url):
        self.session.headers.update({'Referer': BASE_LOGIN_URL})
        req = self.session.get(BASE_URL[:-1] + checkpoint_url, cookies={'ig_cb': '1'})

        self.session.headers.update({'Referer': BASE_URL[:-1] + checkpoint_url,
                          'X-CSRFToken': req.cookies['csrftoken']})
        mode = input('Choose a challenge mode (0 - SMS, 1 - Email): ')
        challenge_data = {'choice': mode}
        csrf_token = req.cookies['csrftoken']
        mid = self.session.cookies['mid']

        self.session.headers.clear()
        self.session.cookies.clear()

        self.session.headers = {
            'Accept-Encoding': 'gzip, deflate, br',
            'User-Agent': CHROME_WIN_UA,
            'Referer': BASE_URL[:-1] + checkpoint_url,
            'X-CSRFToken': csrf_token,
            'X-Instagram-AJAX': '6c1f67754dc0',
            'X-Requested-With': 'XMLHttpRequest'}

        cookies = {
            'csrftoken': csrf_token,
            'ig_cb': '1',
            'mid': mid,
            'rur': 'PRN',
            'mcd': '3'}

        challenge = self.session.post(BASE_URL[:-1] + checkpoint_url, cookies=cookies, data=challenge_data, allow_redirects=True)

        code = input('Enter code received: ')
        code_data = {'security_code': code}
        code = self.session.post(BASE_URL[:-1] + checkpoint_url, cookies=cookies, data=code_data, allow_redirects=True)
        cookies = code.cookies
        code_text = json.loads(code.text)

        if code_text.get('status') == 'ok':
            self.cookies = cookies
        elif 'errors' in code.text:
            for count, error in enumerate(code_text['challenge']['errors']):
                count += 1
                self.logger.error('Session error %(count)s: "%(error)s"' % locals())
        else:
            self.logger.error('Look at login file.')

    # function to handle connection reset by OS
    def __send_request(self, url, params=None, headers=None, cookies=None):
        while True:
            try:
                return requests.get(url, params=params, headers=headers, cookies=cookies)
            except Exception as e:
                self.logger.warn(str(e) + ' Waiting...')
                time.sleep(60)
