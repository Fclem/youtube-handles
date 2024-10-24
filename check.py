#!/bin/env python3

import csv
from glob import glob
from time import sleep

from haralyzer import HarParser
from json import loads
import os
import pickle
from random import randint
import requests
import time
import argparse
import gotify
import datetime


def log_message(message, end="\n"):
	current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	print(f"[{current_time}] {message}", end=end)


class This:
	gotify = None
	pause_time = 600  # interval between checks
	query_count = 0   # number of queries made
	title = "YouTube Username Checker"


class GotifyClient:
	__client = None
	
	def __init__(self, url, key):
		self.url = url
		self.key = key
		
	def client(self) -> gotify.gotify.Gotify:
		if not self.__client:
			self.__client = gotify.Gotify(self.url, self.key)
		return self.__client
	
	def send_raw_message(self, title, message, priority, extras=None):
		self.client().create_message(message, {} if not extras else extras, priority, title)
	
	def send_markdown_message(self, title, message, priority):
		self.send_raw_message(title, message, priority, {"client::display": {"contentType": "text/markdown"}})
	
	def send_text_message(self, title, message, priority):
		self.send_raw_message(title, message, priority)
	
	# def send_message(self, title, message, priority):
	#	self.client().create_message(message, {"client::display": {"contentType": "text/markdown"}}, priority, title)
	
	def send_message(self, message, title=This.title, priority=0):
		self.send_markdown_message(title, message, priority)
	
	
def get_latest_har(log):
	all_files = glob(os.getcwd() + "/*")  # get list of files in own folder
	har_files = []
	for file in all_files:
		# if file is a youtube.com har file, save it
		if file.lower().endswith('.har') and ("youtube.com" in file.lower()):
			har_files.append(file)
	latest_har = max(har_files, key=os.path.getctime)
	if log:
		print(f"using latest HAR file: {latest_har}")
	return latest_har


def import_usernames(filename, log):
	usernames = []
	num_names = 0
	with open(filename) as csv_file:
		for row in csv_file:
			if len(row[:-1]) >= 3:  # don't import usernames less than three chars
				usernames.append(row[:-1])
				num_names += 1
	if log:
		print(f"successfully imported {num_names} usernames from {filename}")
	return usernames


def save_results(results, log):
	with open("results.csv", "w", encoding="UTF8", newline="") as f:
		writer = csv.writer(f)
		writer.writerow(("username", "available"))
		writer.writerows(results)
	if log:
		print(f"successfully saved {len(results)} results")


def convert_headers(headers, want_cookies, log):
	# originally compressed, which postman and ff handled automatically
	# caused quite the headache figuring out why it couldn't be decoded
	unwanted_headers = ["Content-Length", "Accept-Encoding"]
	# if not want_cookies:
	# 	if log:
	# 		print("not using cookies from HAR file")
	# 	unwanted_headers.append("Cookie")
	new_headers = {}
	for kvp in headers:
		if kvp["name"] not in unwanted_headers:
			new_headers[kvp["name"]] = kvp["value"]
	return new_headers


def import_request(filename, want_cookies, log):
	# verify that it was a successful one(?)
	har_parser = HarParser.from_file(filename)
	# there should only be one request collected (for one page)
	target_request = har_parser.pages[0].post_requests[0]
	return target_request.url, \
		   convert_headers(target_request.request.headers, want_cookies, log), \
		   loads(target_request.request["postData"]["text"])


def load_session(log):
	try:  # check if we've already saved updated cookies
		with open("session.pickle", "rb") as f:
			session = pickle.load(f)
	except FileNotFoundError:  # otherwise, use those from HAR
		session = requests.session()  # or an existing session
		if log:
			print("no session found")
		return session, False
	if log:
		print("using existing session from previous usage")
	return session, True


def save_session(session, log):
	with open("session.pickle", "wb") as f:
		pickle.dump(session, f)
	if log:
		print("session successfully saved")


def delete_session(log):
	os.remove("session.pickle")
	if log:
		print("session successfully removed")


def check_username(session, url, headers, payload, username, log):
	payload["handle"] = username  # replace previous username with desired search term
	response = session.post(url, headers=headers, json=payload)
	response_data = loads(response.content)
	# save_session(session, log)  # temporarily disabled
	status = response.status_code  # for passing additional info to main loop of program
	This.query_count += 1
	try:
		if response_data["result"]["channelHandleValidationResultRenderer"]["result"] \
				== "CHANNEL_HANDLE_VALIDATION_RESULT_OK":
			return True, session, status
	except KeyError as err:
		if response.status_code == 401:
			log_message("logged out—saving and shutting down")
		elif response.status_code == 429:
			log_message("rate limit!")
		else:
			log_message(f"unknown error #{status}, save this message: {response.content}")
	return False, session, status


def run_full_search(usernames, log):
	latest_har = get_latest_har(log)
	session, session_existed = load_session(log)
	# if session already existed, we don't collect cookies from HAR
	url, headers, payload = import_request(latest_har, (not session_existed), log)
	results = []
	for username in usernames:
		random_element = randint(0, 9)  # add randomness to sleep time
		time.sleep(random_element)
		success, session, status = check_username(session, url, headers, payload, username, log)
		results.append((username, success))
		if status == 200:
			if not success:
				This.gotify.send_message("the handle **%s** is not available" % username)
			else:
				This.gotify.send_message("The handle **%s** is **available** !!" % username, priority=8)
				exit(0)
		elif status == 429:  # rate limit, slowing down
			This.gotify.send_message(f"Could not check **{username}** due to rate limit", priority=5)
		else:  # something went wrong, exit gracefully
			return results, status
	return results, 200


class ActionRequired(Exception):
	pass


class MissingArgument(Exception):
	pass


def main():
	log = True  # set to true if you want to print program logs
	
	parser = argparse.ArgumentParser(description="Check YouTube usernames availability.")
	parser.add_argument('-u', '--username', type=str, help="username to check for")
	parser.add_argument('--gotify-url', type=str, help="gotify notification url")
	parser.add_argument('--gotify-key', type=str, help="gotify app key")
	# parser.add_argument('-l', '--log', action='store_true', help="Enable logging.")
	args = parser.parse_args()
	
	if not args.gotify_url or not args.gotify_key:
		raise MissingArgument("--gotify-url and --gotify-key are required")
		
	This.gotify = GotifyClient(args.gotify_url, args.gotify_key)
	This.gotify.send_message("Started checking username availability for **%s**" % args.username, priority=5)
	# usernames = ["smelly", "tiola1396u", "lolman"]
	usernames = [args.username]
	while True:
		log_message("Checking for %s #%d..." % (usernames, This.query_count))
		results, status = run_full_search(usernames, log)
		# save_results(results, log)  # log what we have, regardless of whether completed
		if status != 200:  # if something went wrong, search exited early
			if status == 401:  # logged out condition
				# delete_session(log)  # old session is stale, we'll get new one from HAR
				raise ActionRequired("time to download a new HAR file!" + \
								" (youtube logged you out, be careful)")
			elif status == 429:  # rate limit condition
				pass
				#raise ActionRequired("you've been rate limited three times already!" + \
				#				" if I were you, I'd take the rest of the day off")
			else:  # unknown error condition
				raise Exception("unknown error occurred—youtube must've changed their API" + \
								" (please tell me!)")
		log_message("Sleeping for %d seconds..." % This.pause_time)
		sleep(This.pause_time)


if __name__ == "__main__":
	try:
		main()
	except (ActionRequired, Exception) as err:
		prio = 0
		if err.__class__ == ActionRequired:
			prio = 8
		This.gotify.send_message("Error after %d checks: %s" % (This.query_count, err), priority=prio)
		log_message(err)
		exit(1)
