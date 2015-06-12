# wordpress-tls-plugin
A wordpress TLS authentication mechanism Proof Of Concept.

# Apache2 installation
in /etc/apache2/sites-enabled/something-ssl.conf:

SSLVerifyClient require
SSLCertificateFile    /home/cloud/server/$(hostname)-crt
SSLCertificateKeyFile /home/cloud/server/$(hostname)-key
SSLCACertificateFile /home/cloud/ca/ca.crt

Additional requirements, is

#SSLOptions +FakeBasicAuth +ExportCertData +StrictRequire
<FilesMatch "\.(cgi|shtml|phtml|php)$">
	SSLOptions +StdEnvVars +ExportCertData
</FilesMatch>


# Browser
Have the CA above, issue a personal x509 to you and install it into your browser.

# TODO
* Fix, automatic SSL_CLIENT_M_SERIAL, so that the first validated login adds it to the table_mapping.
* Fix, add profile meta box, to allow to choose from certs, and add it to the profile-list, when you are an admin.
* Fix, user-permissions in authenticate-plugin.
* Fix, a lot of fixes, 

