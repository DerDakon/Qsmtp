# Qsmtp

New IPv6 capable SMTP engine for qmail.

Qsmtp is a drop in replacement for the qmail SMTP programs qmail-smtpd and qmail-remote.
That means you just change your startup scripts to use Qsmtpd instead of qmail-smtpd and most things will work as before.
The main difference (beyond the new features) is that Qsmtpd does only look at the custom tcpserver environment variables one may configure in the rules file, therefore setting RELAYCLIENT will not work.
You can use /var/qmail/control/relayclients and /var/qmail/control/relayclients6 to get the same behaviour.
Use the addipbl command to add addresses to these files. If you want to use Qremote instead of qmail-remote just move your qmail-remote binary out of the way and create a symlink from Qremote to qmail-remote.
