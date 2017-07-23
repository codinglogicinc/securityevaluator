# securityevaluator
SecurityEvaluator.com We provide an api that you can use that will allow you to scan your wordpress website to make sure that there are no bad/hacked files on your server. Now for a limited time we are offering our service at 50% off. If you sign up now you will keep the current price for as long as you keep the subscription active. The scanner script is coded in python and made to be used/run as a cronjob every 1 or 2 times a days. This is our python scanner script that is made to be run as a cronjob.

To use this script you need to subscibe to securityevaluator.com

then you set a cronjob to run like
--directory is the full path to your wordpress install directory.
--host is the hostname for the api it should be api.securityevaluator.com
--post we currently only support http so it should be port 80
--api_key is your api key
--api_secret is your api secret

python securityevaluator.py --directory=/home/ubuntu/zips/wordpress-4.1.3/wordpress/ --host=api.securityevaluator.com --port=80 --api_key= 669855ac6d8011e7b225fa163ebbad8f --api_secret=669855ad6d8011e7b225fa163ebbad8f669855ae6d8011e7b225
