from itertools import product
from collections import Counter

from flask import Flask, render_template, request
from difflib import get_close_matches

from constants import TOP_500_DOMAINS

app = Flask(__name__)

# ----------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------     ROUTES     ----------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

@app.route('/task1', methods=['GET', 'POST'])
def task_one():

    if request.method == 'POST':
        result = task_one(request.form['email'], request.form['email-body'])
        return render_template('task1.html', prob=result[0], explanation=result[1])  # returns a tuple containing the prob of the email being a malicious email and the explanation why

    else:
        return render_template('task1.html')


@app.route('/task2', methods=['GET'])
def task_two():
    return render_template('task2.html')


@app.route('/query_one', methods=['GET', 'POST'])
def query_one_input():

    if request.method == 'POST':
        query_one_result = query_one(request.form['search'])  # returns a tuple containing the prob of the query being a malicious query and the explanation why
        return render_template('task2.html', query_one_prob=query_one_result[0], query_one_explanation=query_one_result[1])

    else:
        return render_template('task2.html')


@app.route('/query_two', methods=['GET', 'POST'])
def query_two_input():

    if request.method == 'POST':
        query_two_result = query_two(request.form['username'], request.form['password'])  # returns a tuple containing the prob of the query being a malicious query and the explanation why
        return render_template('task2.html', query_two_prob=query_two_result[0], query_two_explanation=query_two_result[1])

    else:
        return render_template('task2.html')

# ----------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------     END ROUTES    ---------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

def task_one(senders_email, email_text):
    errors = []

    spammy_word_list = ["label", "invoice", "post", "document", "postal", "calculations", "copy", "fedex", "statement",
                        "financial", "dhl", "usps", "8", "notification", "irs", "ups", "no", "delivery", "ticket",
                        "account", "secur", "verif", "com-", "update", "support", "service", "login", "Auth",
                        "confirm", 'urgent', 'login', 'need', 'immediately', 'immediacy', 'right now', 'soon', 'expire', 'expiring',
                        'as soon as possible', 'minutes', 'hours', 'seconds', 'days', 'months', 'urgency', 'account', 'bank', 'offer',
                        'redeem', 'unusual', 'activity']

    email_text_list = email_text.split()  # split the email text into an array of strings
    split_email = senders_email.split('@')  # split the email name from the domain name
    email_name = split_email[0]
    email_domain = split_email[1]

    score, error = domain_spam_score(test_domain=email_domain)

    errors.append(error)

    sus_o_meter = score
    contains_num = False
    contains_spammy_words = False
    spammy_domain = False

    if email_domain in spammy_email_domains: # add 10 to the sus meter if the domain is in our spammy domain list
        spammy_domain = True
        sus_o_meter += 10

    for word in spammy_word_list:  # add 1 to the sus meter if it contains a spammy word
        if word in email_text:
            contains_spammy_words = True
            sus_o_meter += 5

    if contains_number(senders_email):  # add  3 to the sus meter if the email name contains a number
        contains_num = True
        sus_o_meter += 3

# ----- Range check and explanations -----

    if sus_o_meter <= 3:
        prob = sus_o_meter
        explanation = 'Most likely a safe sender.'

        return prob, explanation

    if sus_o_meter > 3 and sus_o_meter <= 5:
        if contains_spammy_words == True:
            prob = sus_o_meter
            explanation = 'This may be a suspicious sender as it contains spammy words'
            return prob, explanation

    if sus_o_meter > 5:
        if contains_spammy_words is True and spammy_domain is True:
            if sus_o_meter > 10:
                prob = 10
            else:
                prob = sus_o_meter
            explanation = 'This is most likely a phishing attack as it contains a spammy email and spammy words'
            return prob, explanation
        elif contains_spammy_words is True and spammy_domain is False:
            prob = sus_o_meter
            explanation = 'This is most likely a phishing attack as it contains lots of spammy words'
            return prob, explanation
        else:
            prob = sus_o_meter
            explanation = 'This is most likely a phishing attack as it contains a spammy email domain'
            return prob, explanation

    return 'error', 'error'


# Tautologies,
# Illegal/Logically Incorrect Queries,
# Union Queries,
# Piggy-backed Queries,
# Inference,
# Alternate Encodings


def query_one(search):

    possible_sql_attacks = ['1=1', 'union', 'login', 'password', 'pass', 'pin', 'drop', 'table', 'username', 'admin', 'shutdown', '1=0', 'waitfor', '--', 'exec']

    if search in possible_sql_attacks:
        prob = 'high'
        explanation = 'The query was not searching for an item, thus it would be blocked.'
        return prob, explanation
    else:
        prob = 'low'
        explanation = 'The query appeared to be searching for an item, thus it would be executed'

        return prob, explanation


def query_two(username, password):
    possible_sql_attacks = ["1=1", "--", "''", "convert", "int", "sysobjects", "xtype", "union", ";", "shutdown", "@", "1=0", "ascii", "substring", "waitfor", "exec", "char", "0x"]

    if username or password in possible_sql_attacks:
        prob = 'high'
        explanation = 'The username and password provided looks like a possible SQL attack'
        return prob, explanation
    else:
        prob = 'low'
        explanation = 'The username and password appear legitimate, thus it would be executed.'
        return prob, explanation

# -------- Helpers ---------
def contains_number(s):
    return any(i.isdigit() for i in s)

def domain_spam_score(test_domain=None):
    if test_domain is None:
        return 100
    test_domain = test_domain.lower()

    #  Domain is in top_500_domains, not spam as far as domain is concerned
    if test_domain in TOP_500_DOMAINS:
        return 0

    #  Check if domain has a spammy prefix/suffix
    for prefix, domain in product(['update', 'login', 'verify'], TOP_500_DOMAINS):
        if test_domain == '{}-{}'.format(prefix, domain) or test_domain == '{}-{}.{}'.format(domain.split('.')[0], prefix, domain.split('.')[-1]):
            return 50, 'From address has a likely phishing domain'

    score = 0
    # Already checked for exact match, so the word is just a close match which is likely spam
    if len(get_close_matches(test_domain, TOP_500_DOMAINS, cutoff=0.75)) > 0:
        for match in get_close_matches(test_domain, TOP_500_DOMAINS):
            counters = [Counter(zip(s, range(len(s)))) for s in [test_domain, match]]
            #  Calculates the number of different letters in each string, less different letters gives a greater score(more likely to be something like f4cebook.com), more gives a smaller score
            num_diff = len(test_domain) - sum((counters[0] & counters[1]).values())
            add_to_score = (1 / num_diff) * 33.33
            score += add_to_score

    if score > 50:
        score = 50
    if len(get_close_matches(test_domain, TOP_500_DOMAINS, cutoff=0.75)) > 0:
        return score, 'Domain is not in list of known domains, but is close to the domain(s) {}'.format(get_close_matches(test_domain, TOP_500_DOMAINS, cutoff=0.75))
    return score + 5, 'Domain is not in list of known domains'


if __name__ == '__main__':
    app.run(debug=True)