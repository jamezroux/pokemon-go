import sys
import imaplib
import getpass
import email
import email.header
import datetime
import base64
import re
import time
import mechanize
import random
import logging
from BeautifulSoup import BeautifulSoup
from faker import Factory

log = logging.getLogger(__name__)

################################################
#             Fill This Stuff Out              #
################################################
IMAP_SERVER = "imap.yourserver.com"            # The IMAP server
EMAIL_ACCOUNT = "mail@yourdomain.com"          # The email account
EMAIL_PASSWORD = "yourpassword"                # The email password
EMAIL_FOLDER = "Inbox"                         # The email folder (default is usually inbox)
PASSWORD_LENGTH = 10                           # Length for the account passwords
MAGIC_DATA = "yourstuff"                       # Extra text to add to the end of all accounts, to make them more unique
DOMAIN_NAME = "yourdomain.com"                 # The domain name for the email accounts (probably the domain name of your bounce email)
SLEEP_TIME = 30                                # Time to sleep in seconds
ACCOUNT_AMOUNT = 1                             # Number of accounts to make
################################################


# This function processes the mailbox
# It searches the mailbox for all emails from noreply@pokemon.com (aka activation linkx)
# It then filters out the activation link, and accesses it. Thus activating the account

def process_mailbox(M):
	log.info('Checking the mailbox.')
	br = mechanize.Browser()
	br.addheaders = [('User-agent', 'Firefox')]

	# Sort through the emails for any from noreply@pokemon.com
	# Todo: Maybe make it a variable, so the script can be used for other stuff...?
	# ^ Probably not, the account creation is specific to the forms

	rv, data = M.search(None, '(FROM "noreply@pokemon.com")')
	if rv != 'OK':
		log.debug('No messages found!')
		return

	# The main loop that gets the emails and activates them

	for num in data[0].split():

                # Attempts the fetch, and attempts again if an error is thrown
                # This previously would cause an error that stopped the script,
                # lets see if it can do it's bullshit this time when I a fuck
                # it with a while loop

                try:
                    rv, data = M.fetch(num, 'RFC822')
                except:
                    log.info('Fetch command failed, restarting the function')
                    process_mailbox(M)
                    break

		if rv != 'OK':
			log.debug('Error getting message')
			return

		msg = email.message_from_string(data[0][1])
		decode = email.header.decode_header(msg['Subject'])[0]
		subject = unicode(decode[0], 'utf-8')
		body = email.message_from_string(data[0][1])

		log.info('Message %s: %s' % (num, subject))

		# IMAP doesn't give the entire email body in one go
		# So, we have to loop through the body if it is larger
		# than one part. Otherwise, it's one part and done

		if body.is_multipart():
			for payload in body.get_payload():

				# Beautiful soup filters out all the href links
				# inside the email bodies, and then I check if
				# the link contains the word "activated", which
				# is in all pokemon go activation links. Then I
				# delete the email.

				soup = BeautifulSoup(payload.get_payload())
				for link in soup.findAll('a'):
					link = link.get('href')
					if "activated" in link:

						# Pretty sure this activates the link, could be fucked later on though
                                                tried = 0
                                                while tried < 5:
                                                    try:
                                                        log.debug('Attempting to activate: %s' % tried)
                                                        br.open(link)
                                                        break
                                                    except:
                                                        tried += 1
					        log.info("%s", link)
                                                M.store(num, '+FLAGS', '\\Deleted')
						M.expunge()

		else:

			# Beautiful soup filters out all the href links
			# inside the email bodies, and then I check if
			# the link contains the word "activated", which
			# is in all pokemon go activation links. Then I
			# delete the email.

			soup = BeautifulSoup(body.get_payload())
			for link in soup.findAll('a'):
				link = link.get('href')
				if "activated" in link:

					# Pretty sure this activates the link, could be fucked later on though
					br.open(link)
                                        tried = 0
                                        while tried < 5:
                                            try:
                                                log.debug('Attempting to activate: %s' % tried)
                                                br.open(link)
                                                break
                                            except:
                                                tried += 1
					log.info("%s", link)
					M.store(num, '+FLAGS', '\\Deleted')
					M.expunge()

	log.debug('Done checking emails')

def email_login(M):

	# Attempts a login with the data supplied in the header
	try:
		rv, data = M.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
	except imaplib.IMAP4.error:
		log.error('Login failed!')
		sys.exit(1)

	# Selects the folder specified in the header
	rv, data = M.select(EMAIL_FOLDER)
	if rv == 'OK':
		log.info('Successful login')
		return True
	else:
		log.error("ERROR: Unable to open mailbox ", rv)
		return False

def create_account(fake):
	log.debug('Creating account')
	br = mechanize.Browser()
	br.addheaders = [('User-agent', 'Firefox')]

        tried = 0
        while tried < 5:
            log.debug('Attempting to open sign-up page: %s' % tried)
            try:
        	br.open("https://club.pokemon.com/us/pokemon-trainer-club/parents/sign-up")
                break
            except:
                tried += 1

	# Submits age, defaults to US as location
	# Todo: Randomize age?

	form = br.select_form("verify-age")

	# These are the form controls
	#
	# csrfmiddlwaretoken -> already set
	# dob -> 1998-03-12
	# country -> ['US']

	dob = br.form.find_control("dob")
	country = br.form.find_control("country")

	dob.value = "1992-03-23"

        tried = 0
        while tried < 5:
            try:
                log.debug('Attempting to submit dob: %s' % tried)
                br.submit()
                break;
            except:
                tried += 1

	#These are the form controls
	#
	# username
	# password
	# confirm_password
	# email
	# confirm_email
	# terms

	form = br.select_form("create-account")

	# Creates a password by magic
	alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	PASSWORD_LENGTH = 10
	password_value = ""
	for i in range(PASSWORD_LENGTH):
		next_index = random.randrange(len(alphabet))
		password_value = password_value + alphabet[next_index]

	# Creates the username with the first letter of a fake name, and 7 letters of a fake last name, with optional data
	two_word_name = "false"

	while(two_word_name == "false"):
		fake_name = fake.name()
		try:
			first_name, last_name = fake_name.split()
			two_word_name = "true"
		except:
			two_word_name = "false"

        username_value = password_value[:4] + last_name[:7] + MAGIC_DATA
	username_value = username_value.lower()
	# Sends an email that is [username]@[domain], make sure to monitor bounce bro
	email_value = username_value + "@" + DOMAIN_NAME

	log.info('Username: %s', username_value)
	log.debug('Password: %s', password_value)
	log.debug('Email: %s', email_value)

	# Sets each form control we will be using as a variable
	username = br.form.find_control("username")
	password = br.form.find_control("password")
        confirm_password = br.form.find_control("confirm_password")
	email = br.form.find_control("email")
	confirm_email = br.form.find_control("confirm_email")
	terms = br.form.find_control("terms")

	# Inputs what we want in the form
	# Todo: Generate usernames, passwords, and emails
	# Todo: Log all logins + emails in a file

	username.value = username_value
	password.value = password_value
	confirm_password.value = password_value
	email.value = email_value
	confirm_email.value = email_value
	terms.items[0].selected = True

        with open("accounts.csv", "a") as account_file:
                account_file.write("%s,%s,%s\n" % (username_value, password_value, email_value))

        tried = 0
        while tried < 5:
            log.debug('Attempting to submit account: %s' % tried)
            try:
        	br.submit()
	        br.close()
                break
            except:
                tried += 1

	log.debug('Account submitted')

def main():
	M = imaplib.IMAP4_SSL(IMAP_SERVER)
	fake = Factory.create()

        logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(module)10s] [%(levelname)5s] %(message)s')
        logging.getLogger("logger").setLevel(logging.DEBUG)

        log.info('Logger has been setup')

        for account_num in range(ACCOUNT_AMOUNT):
            create_account(fake)
            log.info('Created account: %s' % account_num)

        log.info('Waiting')
        time.sleep(SLEEP_TIME)

	email_login(M)
        process_mailbox(M)

        log.info('Waiting for sleepy emails')
        time.sleep(SLEEP_TIME)

        process_mailbox(M)

	M.close()

if __name__ == '__main__':
	main()
