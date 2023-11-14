import random
import ssl
import time

import capmonster_python
import cloudscraper
import requests
import warnings

import ua_generator
import web3

from utils.logger import logger

warnings.filterwarnings("ignore", category=DeprecationWarning)

class TwitterAccount:

    def __init__(self, auth_token, csrf, proxy):

        self.session = self._make_scraper
        self.session.proxies = proxy


        # adapter = requests.adapters.HTTPAdapter(max_retries=5)
        # self.session.mount('http://', adapter)
        # self.session.mount('https://', adapter)

        authorization_token = 'AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'

        self.csrf = csrf
        self.auth_token = auth_token
        self.cookie = f'auth_token={self.auth_token}; ct0={self.csrf}'

        liketweet_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {authorization_token}',
            'x-csrf-token': self.csrf,
            'cookie': self.cookie,
            'X-Twitter-Active-User': 'yes',
            'X-Twitter-Auth-Type': 'OAuth2Session',
            'X-Twitter-Client-Language':'en',
            'User-Agent': ua_generator.generate(device="desktop").text
        }

        self.session.headers.update(liketweet_headers)


    def Tweet(self, text):


        payload = {"variables": {
            "tweet_text": text,
            "dark_request": False,
            "media": {
                "media_entities": [],  # {'media_id': ..., 'tagged_users': []}
                "possibly_sensitive": False
            },
            "withDownvotePerspective": False,
            "withReactionsMetadata": False,
            "withReactionsPerspective": False,
            "withSuperFollowsTweetFields": True,
            "withSuperFollowsUserFields": True,
            "semantic_annotation_ids": []
        }, "features": {
            "tweetypie_unmention_optimization_enabled": True,
            "vibe_api_enabled": True,
            "responsive_web_edit_tweet_api_enabled": True,
            "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
            "view_counts_everywhere_api_enabled": True,
            "longform_notetweets_consumption_enabled": True,
            "tweet_awards_web_tipping_enabled": False,
            "interactive_text_enabled": True,
            "responsive_web_text_conversations_enabled": False,
            "responsive_web_twitter_blue_verified_badge_is_enabled": True,
            "responsive_web_graphql_exclude_directive_enabled": False,
            "verified_phone_label_enabled": False,
            "freedom_of_speech_not_reach_fetch_enabled": False,
            "standardized_nudges_misinfo": True,
            "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": False,
            "responsive_web_graphql_timeline_navigation_enabled": True,
            "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
            "responsive_web_enhance_cards_enabled": False
        },
            "queryId": "Tz_cZL9zkkY2806vRiQP0Q"
        }

        response = self.session.post("https://api.twitter.com/graphql/Tz_cZL9zkkY2806vRiQP0Q/CreateTweet", json=payload)
        # print(response.text)
        return response.json()

    @property
    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

class Model:

    def __init__(self, address, twitter_auth, twitter_ct0, proxy, logger):
        self.logger = logger
        self.access_token = None
        self.refresh_token = None
        self.password_ = None

        self.ua = self.generate_user_agent
        self.twitter_auth, self.twitter_ct0 = twitter_auth, twitter_ct0

        self.address = address
        self.session = self._make_scraper
        self.proxy = proxy
        self.session.proxies = {"http": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}",
                                "https": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}"}
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.session.headers.update({"user-agent": self.ua,
                                     'content-type': 'application/json',
                                     'Dnt':'1'})

    def ConfirmPost(self, link):

        with self.session.get(f'https://protocol.beb.quest/utils/verfy-riddle?type=twitter&address={self.address}&url={link}') as response:

            return response.json()['success']

    def GetInvite(self) -> str:

        with self.session.get(f'https://protocol.beb.quest/utils/get-riddle?address={self.address}') as response:
            # print(response.text)
            return response.json()['inviteCode']

    @property
    def generate_user_agent(self) -> str:
        return ua_generator.generate(platform="windows").text

    @property
    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

if __name__ == '__main__':

    proxies = []
    addresses = []
    twitterData = []

    delay = None

    try:
        with open('config', 'r', encoding='utf-8') as file:
            for i in file:
                if 'delay=' in i.rstrip():
                    delay = (int(i.rstrip().split('delay=')[-1].split('-')[0]),
                                int(i.rstrip().split('delay=')[-1].split('-')[1]))

    except:
        # traceback.print_exc()
        print('Вы неправильно настроили конфигуратор, повторите попытку')
        input()
        exit(0)


    with open('InputData/Proxies.txt', 'r') as file:
        for i in file:
            proxies.append(i.rstrip())
    with open('InputData/Addresses.txt', 'r') as file:
        for i in file:
            addresses.append(i.rstrip())
    with open('InputData/TwitterCookies.txt', 'r') as file:
        for i in file:
            twitterData.append(
                [i.rstrip().split('auth_token=')[-1].split(';')[0], i.rstrip().split('ct0=')[-1].split(';')[0]])

    c = 0
    while c < len(twitterData):

        try:
            acc = Model(web3.Web3.to_checksum_address(addresses[c]),
                          twitterData[c][0],
                          twitterData[c][1],
                          proxies[c],
                          logger)

            twModel = TwitterAccount(acc.twitter_auth, acc.twitter_ct0, acc.session.proxies)

            code = acc.GetInvite()
            data = twModel.Tweet(f"Beginning my adventure on farquest.app/?invite={code} with my lil' FarStray on @bebprotocol!")

            result = acc.ConfirmPost(f"https://twitter.com/{data['data']['create_tweet']['tweet_results']['result']['core']['user_results']['result']['legacy']['screen_name']}/status/{data['data']['create_tweet']['tweet_results']['result']['rest_id']}")
            if result:
                logger.success(f'{addresses[c]} | Готов')
            else:
                logger.error(f'{addresses[c]} | Неудача')

        except Exception as e:
            logger.error(f'{addresses[c]} | Ошибка ({str(e)})')


        c+=1
        time.sleep(random.randint(delay[0], delay[1]))

    input('\n\nСкрипт завершил работу')