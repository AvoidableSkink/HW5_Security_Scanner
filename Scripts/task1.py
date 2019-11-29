
senders_email = input("Enter in your email address: ")
email_text  = input("Enter in the message you would like to send: ")

spammy_email_domains = ["apple-com", "applecom", "apple.con", "appie.com", "app-le.com", "pavpal.com", "puaypal.com", "pauypal.com",
                      "paypal-com", "paypai.com", "wellsf.argo.com", "Iclod.com", "icloud-com", "1cloud.com", "lcloud.com",
                      "apple-id.com", "apple.id.com", "appleld.com", "appieid.com", "applid.com", "facbook.com", "ficebook.com", "faceboook.com", "facebo0k.com",
                      "faceebook.com", "amazo.com", "amazn.com", "a-mazon.com", "amzon.com", "microsft.com", "gooogle.com", "gogle.com", "americaexpress.com"]

spammy_word_list = ["label", "invoice", "post", "document", "postal", "calculations", "copy", "fedex", "statement",
                    "financial", "dhl", "usps", "8", "notification", "irs", "ups", "no", "delivery", "ticket",
                    "account", "secur", "verif", "com-", "update", "support", "service", "login", "Auth", "confirm",]

email_text_list = email_text.split()  # split the email text into an array of strings
split_email = senders_email.split('@')  # split the email name from the domain name
email_name = split_email[0]
email_domain = split_email[1]

# if we are thrown a curve ball change it to .com
email_domain = email_domain.replace('.net', '.com')
email_domain = email_domain.replace('.edu', '.com')
email_domain = email_domain.replace('.org', '.com')

sus_o_meter = 0
spammy_word_count = 0
contains_num = False

if email_domain in spammy_email_domains:
    print("you finna be hacked")

for word in spammy_word_list:  # add 1 to the sus meter if it contains a spammy word
    if word in email_text:
        sus_o_meter += 1

if not senders_email.isalpha():  # add  3 to the sus meter if the email name contains a number
    contains_num = True
    sus_o_meter += 3

print("The following email is likely to be a phishing email ")