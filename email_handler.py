


import smtplib
from email.mime.text import MIMEText

import settings




class EmailSender():
    """
    Email sending handler
    """
    def __init__(self):
        self.recipients = settings.DAILY_TRACKER_RECIPIENTS
        self.username = settings.GMAIL_USERNAME
        self.password = settings.GMAIL_PASSWORD
        self.session = None
        self.session_loaded = False
        if not self.username and not self.password:
            print("[*] Please configure username and password for Gmail auth before using! Quitting!")
            return
        else:
            self.init_email_login()


    def init_email_login(self):
        """ Auth and establish email session used for sending emails.
        """
        self.session = smtplib.SMTP('smtp.gmail.com', 587)
        # self.session = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        self.session.ehlo()
        self.session.starttls()
        self.session.login(self.username, self.password)
        self.session_loaded = True
        print("[*] Email authenticated session established!")


    # def send_daily_tracker_email(self, tracker_data):
    #     """
    #     Format the tracker data into email message format and send.
    #     """
    #     if not tracker_data:
    #         print("[ERR] Tracker data is empty, nothing to send.")
    #         return

    #     subject = "CVE Tracker Daily Update"

    #     full_message = "Hello,\nCVE daily watchlist is below:\n"

    #     for cve_results in tracker_data:
    #         # cve_results is a dict of {cve: [Repository dataclasses, ...]}
    #         full_message += f"\n\n\n{cve}:\n"

    #         table_data = f"\n{'Stars':<10}{'Language':<14}{'Name':<45}\n"
    #         table_data += "-" * 90 + '\n'
    #         # NOTE: According to timeit, next() is more speed efficient than list() for this
    #         # cve = list(item.keys())[0]
    #         cve = next(iter(cve_results))
    #         # print(f"CVE: {cve}")
    #         for repo in cve_results.values():
    #             table_data += f"{repo.stars:<10}{repo.language:<14}{repo.full_name:<45}\n"
    #         table_data += "-" * 90 + '\n'
    #         full_message += table_data

    #     full_message += "\n\n\nThank you for using Pocman!\n- Read more: https://www.github.com/Cashiuus/pocman"

    #     self.send_email(subject, full_message)
    #     return


    def send_email(self, subject, message):
        """
        Send an email that contains the provided text body message.

        """
        if not self.session_loaded:
            print("[ERR] Failed to establish Email sender connection for sending email. Check and try again!")
            return
        if not self.recipients:
            return

        # subject = "CVE Tracker Daily Update"
        # body = f"{subject}\n{message}"

        # Format entire message for sending
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = self.username
        msg['To'] = ', '.join(self.recipients)

        print("[*] Sending email")
        send_status = self.session.sendmail(
            self.username,
            self.recipients,
            msg.as_string(),
        )

        if send_status != {}:
            print(f"Response contains error message: {send_status}")


    def shutdown(self):
        self.session.quit()
# -=- End of Class -=-




if __name__ == '__main__':
    obj = EmailSender()

    obj.send_daily_tracker_email()
