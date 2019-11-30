from flask import Flask, render_template, request

app = Flask(__name__)

# ----------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------     ROUTES     ----------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

@app.route('/task1', methods=['GET', 'POST'])
def task_one():

    if request.method == 'POST':
        result = task_one(request.form['email'], request.form['email-body'])
        return render_template('task1.html', prob=result[0], explaination=result[1])  # returns a tuple containing the prob of the email being a malicious email and the explaination why

    else:
        return render_template('task1.html')


@app.route('/task2', methods=['GET'])
def task_two():
    return render_template('task2.html')


@app.route('/query_one', methods=['GET', 'POST'])
def query_one_input():

    if request.method == 'POST':
        query_one_result = query_one(request.form['search'])  # returns a tuple containing the prob of the query being a malicious query and the explaination why
        return render_template('task2.html', query_one_prob=query_one_result[0], query_one_explaination=query_one_result[1])

    else:
        return render_template('task2.html')


@app.route('/query_two', methods=['GET', 'POST'])
def query_two_input():

    if request.method == 'POST':
        query_two_result = query_two(request.form['username'], request.form['password'])  # returns a tuple containing the prob of the query being a malicious query and the explaination why
        return render_template('task2.html', query_two_prob=query_two_result[0], query_two_explaination=query_two_result[1])

    else:
        return render_template('task2.html')

# ----------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------     END ROUTES    ---------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

def task_one(senders_email, email_text):

    spammy_email_domains = ["apple-com", "applecom", "apple.con", "appie.com", "app-le.com", "pavpal.com",
                            "puaypal.com", "pauypal.com",
                            "paypal-com", "paypai.com", "wellsf.argo.com", "Iclod.com", "icloud-com", "1cloud.com",
                            "lcloud.com",
                            "apple-id.com", "apple.id.com", "appleld.com", "appieid.com", "applid.com", "facbook.com",
                            "ficebook.com", "faceboook.com", "facebo0k.com",
                            "faceebook.com", "amazo.com", "amazn.com", "a-mazon.com", "amzon.com", "microsft.com",
                            "gooogle.com", "gogle.com", "americaexpress.com"]

    spammy_word_list = ["label", "invoice", "post", "document", "postal", "calculations", "copy", "fedex", "statement",
                        "financial", "dhl", "usps", "8", "notification", "irs", "ups", "no", "delivery", "ticket",
                        "account", "secur", "verif", "com-", "update", "support", "service", "login", "Auth",
                        "confirm", ]

    email_text_list = email_text.split()  # split the email text into an array of strings
    split_email = senders_email.split('@')  # split the email name from the domain name
    email_name = split_email[0]
    email_domain = split_email[1]

    # if we are thrown a curve ball change it to .com
    email_domain = email_domain.replace('.net', '.com')
    email_domain = email_domain.replace('.edu', '.com')
    email_domain = email_domain.replace('.org', '.com')

    sus_o_meter = 0
    contains_num = False
    contains_spammy_words = False
    spammy_domain = False

    if email_domain in spammy_email_domains: # add 10 to the sus meter if the domain is in our spammy domain list
        spammy_domain = True
        sus_o_meter += 10

    for word in spammy_word_list:  # add 1 to the sus meter if it contains a spammy word
        if word in email_text:
            contains_spammy_words = True
            sus_o_meter += 1

    if not senders_email.isalpha():  # add  3 to the sus meter if the email name contains a number
        contains_num = True
        sus_o_meter += 3

# -------

    if sus_o_meter <= 3:
        prob = sus_o_meter
        explaination = 'Most likely a safe sender.'

        return prob, explaination

    if sus_o_meter > 3 and sus_o_meter <= 5:
        if contains_spammy_words == True:
            prob = sus_o_meter
            explaination = 'This may be a suspicious sender as it contains spammy words'
            return prob, explaination

    if sus_o_meter > 5:
        if contains_spammy_words is True and spammy_domain is True:
            if sus_o_meter > 10:
                prob = 10
            else:
                prob = sus_o_meter
            explaination = 'This is most likely a phishing attack as it contains a spammy email and spammy words'
            return prob, explaination
        elif contains_spammy_words is True and spammy_domain is False:
            prob = sus_o_meter
            explaination = 'This is most likely a phishing attack as it contains lots of spammy words'
            return prob, explaination
        else:
            prob = sus_o_meter
            explaination = 'This is most likely a phishing attack as it contains a spammy email domain'
            return prob, explaination


def query_one(search):

    prob = 'INSERT PROB HERE'
    explaination = 'INSERT EXPLAINATION HERE'

    return prob, explaination


def query_two(username, password):

    prob = 'INSERT PROB HERE'
    explaination = 'INSERT EXPLAINATION HERE'

    return prob, explaination


if __name__ == '__main__':
    app.run(debug=True)