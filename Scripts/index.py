import re
from itertools import product
from collections import Counter

from flask import Flask, render_template, request
from difflib import get_close_matches

from constants import TOP_500_DOMAINS, PHISHING_LIST

app = Flask(__name__)

# ----------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------     ROUTES     ----------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

@app.route('/task1', methods=['GET', 'POST'])
def task_one():

    if request.method == 'POST':
        prob, explanations = task_one(request.form['email'], request.form['email-body'])
        return render_template('task1.html.j2', prob=prob, explanations=explanations, email=request.form['email'], body=request.form['email-body'])  # returns a tuple containing the prob of the email being a malicious email and a list of explanations why

    else:
        return render_template('task1.html.j2')


@app.route('/task2', methods=['GET'])
def task_two():
    return render_template('task2.html.j2')


@app.route('/query_one', methods=['GET', 'POST'])
def query_one_input():

    if request.method == 'POST':
        prob, explanations = query_one(request.form['search'])  # returns a tuple containing the prob of the query being a malicious query and the explanation why
        return render_template('task2.html.j2', query_one_prob=prob, query_one_explanation=explanations, query_one=request.form['search'])

    else:
        return render_template('task2.html.j2')


@app.route('/query_two', methods=['GET', 'POST'])
def query_two_input():


    if request.method == 'POST':
        prob, explanations = query_two(request.form['username'], request.form['password'])   # returns a tuple containing the prob of the query being a malicious query and the explanation why
        return render_template('task2.html.j2', query_two_prob=prob, query_two_explanation=explanations, query_two_username=request.form['username'], query_two_password=request.form['password'])

    else:
        return render_template('task2.html.j2')

# ----------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------     END ROUTES    ---------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

def task_one(senders_email, email_text):
    errors = []

    sus_o_meter = 0
    contains_num = False
    contains_spammy_words = False
    contains_all_upper_words = False
    contains_dollar_signs = False
    spammy_domain = False

    email_text_list = email_text.split()  # split the email text into an array of strings
    split_email = senders_email.split('@')  # split the email name from the domain name
    email_name = split_email[0]
    email_domain = split_email[1]

    domain_score, error = domain_spam_score(test_domain=email_domain)

    if error is not None:
        errors.append(error)

    if domain_score > 10:
        spammy_domain = True
    sus_o_meter += domain_score

    for word in email_text_list:
        if any([spam_word in word.lower() for spam_word in PHISHING_LIST]): #  This guarantees that we will catch partial words.
            if not contains_spammy_words:
                errors.append('Email contains words which are common in phishing attacks')
            contains_spammy_words = True
            sus_o_meter += 5
        if word.isalpha() and word == word.upper():
            if not contains_all_upper_words:
                errors.append('Email contains words in all upper')
            contains_all_upper_words = True
            sus_o_meter += 1
        if '$' in word:
            if not contains_dollar_signs:
                errors.append('Email contains dollar signs')
            contains_dollar_signs = True
            sus_o_meter += 1

    if contains_number(senders_email):  # add  3 to the sus meter if the email name contains a number
        contains_num = True
        errors.append('Email contains a number')
        sus_o_meter += 3

# ----- Range check and explanations -----
    if sus_o_meter > 100:
        sus_o_meter = 100

    if sus_o_meter <= 10:
        return sus_o_meter, errors

    if sus_o_meter > 10 and sus_o_meter <= 20:
        if contains_spammy_words == True:
            return sus_o_meter, errors

    if sus_o_meter > 20:
        return sus_o_meter, errors

    return 100, 'error'


# Tautologies,
# Illegal/Logically Incorrect Queries,
# Union Queries,
# Piggy-backed Queries,
# Inference,
# Alternate Encodings


def query_one(search):
    explanations = []
    badness_score = 0
    has_possible_bad_quotes = False
    has_possible_tautology = False

    has_possible_bad_quotes, score = possible_bad_quotes(search)
    if has_possible_bad_quotes:
        explanations.append('The query contains a possible incorrect number of quotes')
    badness_score += score
    has_possible_tautology, score = possible_tautology(search)
    if has_possible_tautology:
        explanations.append('The query contains a possible tautology attack')
    badness_score += score

    possible_sql_attacks = ['1=1', 'union', 'login', 'password', 'pass', 'pin', 'drop', 'table', 'username', 'admin', 'shutdown', '1=0', 'waitfor', '--', 'exec']

    if search in possible_sql_attacks:
        badness_score += 80
        explanations.append('The query was not searching for an item, thus it would be blocked.')
    return badness_score, explanations


def query_two(username, password):
    explanations = []
    badness_score = 0
    has_possible_bad_quotes = False
    has_possible_tautology = False

    has_possible_bad_quotes, score = possible_bad_quotes(username)
    if has_possible_bad_quotes:
        explanations.append('The query contains a possible incorrect number of quotes')
    badness_score += score
    has_possible_tautology, score = possible_tautology(username)
    if has_possible_tautology:
        explanations.append('The query contains a possible tautology attack')
    badness_score += score

    possible_sql_attacks = ["1=1", "--", "''", "convert", "int", "sysobjects", "xtype", "union", ";", "shutdown", "@", "1=0", "ascii", "substring", "waitfor", "exec", "char", "0x"]

    if username in possible_sql_attacks:
        badness_score += 80
        explanations.append('The username and password provided looks like a possible SQL attack')
    return badness_score, explanations

# -------- Helpers ---------
def contains_number(s):
    return any(i.isdigit() for i in s)

def possible_bad_quotes(test_string):
    if test_string.count("'") % 2 != 0:
        return True, 10 #  Could be an attack
    return False, 0

def possible_tautology(test_string):
    regex = r'[\w\']+=[\w\']+'
    matches = re.findall(regex, test_string, re.MULTILINE)
    for match in matches:
        sides = match.split('=')
        if len(sides) > 1 and sides[0] == sides[1]:
            return True, 10
    return False, 0

def domain_spam_score(test_domain=None):
    if test_domain is None:
        return 50, 'No domain inserted'
    test_domain = test_domain.lower()

    #  Domain is in top_500_domains, not spam as far as domain is concerned
    if test_domain in TOP_500_DOMAINS:
        return 0, None

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
    return score + 5, 'Domain is not in list of known domains, be careful what kind of information you send to this address'


if __name__ == '__main__':
    app.run(debug=True)