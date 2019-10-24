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

    # need both username and user_id to obtain the posts
    def get_posts(self, instagram_profile, user_id):

        min_timestamp = int(datetime(2018, 11, 1).strftime('%s'))

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
            ('variables', '{"id":"' + str(user_id) + '","first":' + str() + '}'),
        )

        posts_query = self.__send_request('https://www.instagram.com/graphql/query/', params=params, headers=headers,
                                   cookies=cookies)

        posts_data = json.loads(posts_query.content)
        more_pages = posts_data['data']['user']['edge_owner_to_timeline_media']['page_info']['has_next_page']
        total_posts = posts_data['data']['user']['edge_owner_to_timeline_media']['count']
        posts = posts_data['data']['user']['edge_owner_to_timeline_media']['edges']

        # self.logger.info('Total posts: {}'.format(total_posts))

        Nposts = 0
        for item in posts:

            id_post = bson.int64.Int64(item['node']['id'])
            last_post_collected_timestamp = item['node']['taken_at_timestamp']
            is_old_post = self.db['post'].find_one({'id_2': id_2, 'id_post': id_post})
            if last_post_collected_timestamp >= min_timestamp and is_old_post is None:
                item_posts = {}
                item_posts['id_post'] = id_post

                if item['node']['edge_media_to_caption']['edges']:
                    item_posts['caption'] = filterString(
                        item['node']['edge_media_to_caption']['edges'][0]['node']['text'])
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

                # post = (item_posts['id_post'], id_mibact, id_2, instagram_profile, item_posts['id_user'],
                #        item_posts['video_count'], item_posts['comments'], item_posts['likes'],
                #        item_posts['img_url'], item_posts['link_post'], item_posts["caption"],
                #        item_posts["date"], item_posts["timestamp"], item_posts["shortcode"],
                #        item_posts["is_video"])
                # self.writer['content'].writerow(post)

                item_posts['id_mibact'] = id_mibact
                item_posts['id_2'] = id_2
                item_posts['username'] = instagram_profile

                try:
                    self.db['post'].insert_one(item_posts)
                    Nposts += 1
                except Exception as e:
                    self.logger.warn('MongoDB Error: ' + type(e).__name__)

            else:
                # self.logger.info('Last post collected found!')
                self.logger.info('{}: {}'.format(metadata['ig_profile'], Nposts))
                return 0

        # Iterate until finish
        while more_pages:
            end_cursor = posts_data['data']['user']['edge_owner_to_timeline_media']['page_info']['end_cursor']

            params = (

                ('query_id', str(queryIdPosts)),
                ('variables',
                 '{"id":"' + str(user_id) + '","first":' + str(N_POSTS) + ',"after":"' + str(end_cursor) + '" }')
            )

            posts_query = self.__send_request('https://www.instagram.com/graphql/query/', params=params, headers=headers,
                                       cookies=cookies)

            posts_data = json.loads(posts_query.content)
            posts = posts_data['data']['user']['edge_owner_to_timeline_media']['edges']
            for item in posts:
                id_post = bson.int64.Int64(item['node']['id'])
                last_post_collected_timestamp = item['node']['taken_at_timestamp']
                is_old_post = self.db['post'].find_one({'id_2': id_2, 'id_post': id_post})
                if last_post_collected_timestamp >= min_timestamp and is_old_post is None:  # int(item_posts['id_post']) not in old_post_ids:
                    item_posts = {}
                    item_posts['id_post'] = id_post

                    if item['node']['edge_media_to_caption']['edges']:
                        item_posts['caption'] = filterString(
                            item['node']['edge_media_to_caption']['edges'][0]['node']['text'])
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

                    # post = (item_posts['id_post'], id_mibact, id_2, instagram_profile, item_posts['id_user'],
                    #        item_posts['video_count'], item_posts['comments'], item_posts['likes'],
                    #        item_posts['img_url'], item_posts['link_post'], item_posts["caption"],
                    #        item_posts["date"], item_posts["timestamp"], item_posts["shortcode"],
                    #        item_posts["is_video"])
                    # self.writer['content'].writerow(post)

                    item_posts['id_mibact'] = id_mibact
                    item_posts['id_2'] = id_2
                    item_posts['username'] = instagram_profile

                    try:
                        self.db['post'].insert_one(item_posts)
                        Nposts += 1
                    except Exception as e:
                        print 'MongoDB Error: ' + type(e).__name__

                else:
                    #print ('Last post collected found!')
                    self.logger.info('{}: {}'.format(metadata['ig_profile'], Nposts))
                    return 0

            more_pages = posts_data['data']['user']['edge_owner_to_timeline_media']['page_info']['has_next_page']
            time.sleep(3)

        return 1

    def get_tag(self, instagram_tag, target_date):

        min_timestamp = int(target_date.strftime('%s'))

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

        posts_query = self.__send_request('https://www.instagram.com/graphql/query/', params=params, headers=headers,
                                   cookies=cookies)

        posts_data = json.loads(posts_query.content)
        more_pages = posts_data['data']['hashtag']['edge_hashtag_to_media']['page_info']['has_next_page']
        posts = posts_data['data']['hashtag']['edge_hashtag_to_media']['edges']

        posts_collected = 0
        posts_scraped = 0
        for item in posts:
            posts_scraped += 1

            id_post = bson.int64.Int64(item['node']['id'])
            last_post_collected_timestamp = item['node']['taken_at_timestamp']

            old_post = self.db['tag'].find_one({'id_post': id_post})
            if last_post_collected_timestamp >= min_timestamp and old_post is None:
                item_posts = {}
                item_posts['id_post'] = id_post

                if item['node']['edge_media_to_caption']['edges']:
                    item_posts['caption'] = filterString(
                        item['node']['edge_media_to_caption']['edges'][0]['node']['text'])
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

                item_posts['hashtag'] = [instagram_tag]

                try:
                    self.db['tag'].insert_one(item_posts)
                    posts_collected = posts_collected + 1
                except Exception as e:
                    print 'MongoDB Error: ' + type(e).__name__

            elif last_post_collected_timestamp >= min_timestamp and old_post is not None:
                if instagram_tag not in old_post['hashtag']:
                    res = self.db['tag'].update_one({'id_post': old_post['id_post']}, {'$push': {'hashtag': instagram_tag}}, upsert=False)
                    self.logger.warn('Post already present: updated hashtag list')

        # self.logger.info(datetime.fromtimestamp(int(item['node']['taken_at_timestamp'])).strftime('%Y-%m-%d %H:%M:%S'))

        # count number of loops without any of the target timestamps
        useless_loops = 0
        while more_pages and useless_loops < MAX_LOOPS:
            end_cursor = end_cursor = posts_data['data']['hashtag']['edge_hashtag_to_media']['page_info']['end_cursor']

            params = (

                ('query_hash', QUERY_HASH),
                ('variables',
                 '{"tag_name":"' + instagram_tag + '","first":' + str(N_POSTS) + ',"after":"' + str(
                     end_cursor) + '" }')
            )

            posts_query = self.__send_request('https://www.instagram.com/graphql/query/', params=params, headers=headers,
                                       cookies=cookies)

            posts_data = json.loads(posts_query.content)
            posts = posts_data['data']['hashtag']['edge_hashtag_to_media']['edges']

            found_one = False
            for item in posts:
                posts_scraped += 1

                id_post = bson.int64.Int64(item['node']['id'])
                last_post_collected_timestamp = item['node']['taken_at_timestamp']
                old_post = self.db['tag'].find_one({'id_post': id_post})

                if last_post_collected_timestamp >= min_timestamp and old_post is None:

                    found_one = True

                    item_posts = {}
                    item_posts['id_post'] = id_post

                    if item['node']['edge_media_to_caption']['edges']:
                        item_posts['caption'] = filterString(
                            item['node']['edge_media_to_caption']['edges'][0]['node']['text'])
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

                    item_posts['hashtag'] = [instagram_tag]

                    try:
                        self.db['tag'].insert_one(item_posts)
                        posts_collected = posts_collected + 1
                    except Exception as e:
                        self.logger.warn('MongoDB Error: ' + type(e).__name__)

                elif last_post_collected_timestamp >= min_timestamp and old_post is not None:
                    if instagram_tag not in old_post['hashtag']:
                        res = self.db['tag'].update_one({'id_post': old_post['id_post']}, {'$push': {'hashtag': instagram_tag}}, upsert=False)
                        self.logger.warn('Post already present: updated hashtag list')

            # print datetime.fromtimestamp(int(item['node']['taken_at_timestamp'])).strftime('%Y-%m-%d %H:%M:%S')

            more_pages = posts_data['data']['hashtag']['edge_hashtag_to_media']['page_info']['has_next_page']
            if not found_one:
                useless_loops = useless_loops + 1

            time.sleep(3)

        self.logger.info('OFFICIAL TAG - #{}: {}'.format(instagram_tag, posts_collected))

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
