
senders_email = input("Enter in your email address: ")
email_text  = input("Enter in the message you would like to send: ")

spammy_email_domains = ["apple-com", "applecom", "apple.con", "appie.com", "app-le.com", "pavpal.com", "puaypal.com", "pauypal.com",
                      "paypal-com", "paypai.com", "wellsf.argo.com", "Iclod.com", "icloud-com", "1cloud.com", "lcloud.com",
                      "apple-id.com", "apple.id.com", "appleld.com", "appieid.com", "applid.com", "facbook.com", "ficebook.com", "faceboook.com", "facebo0k.com",
                      "faceebook.com", "amazo.com", "amazn.com", "a-mazon.com", "amzon.com", "microsft.com", "gooogle.com", "gogle.com", "americaexpress.com"]

spammy_word_list = ["label", "invoice", "post", "document", "postal", "calculations", "copy", "fedex", "statement",
                    "financial", "dhl", "usps", "8", "notification", "n", "irs", "ups", "no", "delivery", "ticket",
                    "account", "secur", "verif", "com-", "update", "support", "service", "login", "Auth", "confirm"]

email_text_list = email_text.split()  # split the email text into an array of strings
split_email = senders_email.split('@')  # split the email name from the domain name
email_domain = split_email[1]

# if we are thrown curve ball changes it to .com
email_domain = email_domain.replace('.net', '.com')
email_domain = email_domain.replace('.edu', '.com')
email_domain = email_domain.replace('.org', '.com')


if email_domain in spammy_email_domains:
    print("you finna be hacked")


spammy_word_count = 0
for word in email_text_list:
    for other_word in spammy_word_list:
        if word == other_word:
            spammy_word_count += 1

print(spammy_word_count)