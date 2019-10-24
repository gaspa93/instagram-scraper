from dateutil.relativedelta import relativedelta
import time
import json
import re
import requests
from datetime import date, timedelta, datetime

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

    def __init__(self, db_client, c, logger, s=None):
        self.db = db_client
        # self.writer = w
        self.login_ = c
        self.logger = logger
        self.session = s

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

    def get_account_by_usenrame(self, instagram_profile):

        url = 'https://www.instagram.com/' + instagram_profile

        page = self.__send_request(url)
        json_data = re.findall(r'window._sharedData = (.*?);</script>', page.text)
        data = json.loads(json_data[0])

        u = data['entry_data']['ProfilePage'][0]['graphql']['user']
        if u['biography'] is not None:
            u['biography'] = filterString(u['biography'])
        u['n_posts'] = int(re.findall(r'content=\"(.*?)\sFollowers,\s(.*?)\sFollowing,\s(.*?)\sPosts\s',
                                           page.text.encode('utf-8'))[0][2].replace(",", "").replace(".", "").replace("k", "000"))

        self.db['user'].insert_one(u)

        return 1

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


    def __get_post_data(self, posts, min_timestamp):

        Nposts = 0
        for item in posts:

            id_post = bson.int64.Int64(item['node']['id'])
            last_post_collected_timestamp = item['node']['taken_at_timestamp']
            if last_post_collected_timestamp >= min_timestamp:
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
                    Nposts += 1
                except Exception as e:
                    self.logger.warn('MongoDB Error: ' + type(e).__name__)

            else:
                self.logger.info('Posts collected: {}'.format(Nposts))
                return 1

        return 0

    # need both username and user_id to obtain the posts
    def get_posts(self, instagram_profile, user_id, min_timestamp):

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
        stop = self.__get_post_data(posts, min_timestamp)

        # Iterate until finish
        while more_pages and not stop:

            params = (

                ('query_id', str(queryIdPosts)),
                ('variables',
                 '{"id":"' + str(user_id) + '","first":' + str(N_POSTS) + ',"after":"' + str(end_cursor) + '" }')
            )

            posts, more_pages, end_cursor= self.__query_ig(params, headers, cookies)
            stop = self.__get_post_data(posts, min_timestamp)

            # wait before next request
            time.sleep(3)

        return 1

    def get_tag(self, instagram_tag, n_to_scrape):

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
        stop = self.__get_post_data(posts, min_timestamp)

        while more_pages and not stop:

            params = (

                ('query_hash', QUERY_HASH),
                ('variables',
                 '{"tag_name":"' + instagram_tag + '","first":' + str(N_POSTS) + ',"after":"' + str(
                     end_cursor) + '" }')
            )

            posts, more_pages, end_cursor= self.__query_ig(params, headers, cookies, qtype='hashtag')
            stop = self.__get_post_data(posts, min_timestamp)

            time.sleep(3)

        return 1

    def __get_shared_data(self, username):
        """Fetches the user's metadata."""
        resp = self.session.get(BASE_URL + username).text

        if resp is not None and '_sharedData' in resp:
            try:
                shared_data = resp.split("window._sharedData = ")[1].split(";</script>")[0]
                return json.loads(shared_data)
            except (TypeError, KeyError, IndexError):
                pass

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

    # to handle connection reset by OS
    def __send_request(self, url, params=None, headers=None, cookies=None):
        while True:
            try:
                return requests.get(url, params=params, headers=headers, cookies=cookies)
            except Exception as e:
                self.logger.warn(str(e) + ' Waiting...')
                time.sleep(60)
