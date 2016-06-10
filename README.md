# wordpress-tls-plugin for wordpress-4.4
 A wordpress TLS authentication mechanism Proof Of Concept.

# Apache2 installation
 in /etc/apache2/sites-enabled/something-ssl.conf:

 SSLVerifyClient require
 SSLCertificateFile    /home/cloud/server/$(hostname)-crt
 SSLCertificateKeyFile /home/cloud/server/$(hostname)-key
 SSLCACertificateFile /home/cloud/ca/ca.crt

 Additional requirements, is

 # SSLOptions +FakeBasicAuth +ExportCertData +StrictRequire
 <FilesMatch "\.(cgi|shtml|phtml|php)$">
	SSLOptions +StdEnvVars +ExportCertData
 </FilesMatch>

# Nginx

    server {
    ssl on;
    ..
    ..
    ssl_verify_client optional;


    location ~ \.php$ { # (or other extension)

	fastcgi_split_path_info ^(.+\.php)(/.+)$;
	# NOTE: You should have "cgi.fix_pathinfo = 0;" in php.ini
	
	# With php5-cgi alone:
	# fastcgi_pass 127.0.0.1:9000;

	# With php5-fpm:
	fastcgi_pass unix:/var/run/php5-fpm.sock;
	fastcgi_index index.php;
	include fastcgi_params;

        # Fix ssl client certificate
        fastcgi_param  SSL_CLIENT_VERIFY $ssl_client_verify;
        fastcgi_param  SSL_CLIENT_S_DN $ssl_client_s_dn;
        fastcgi_param  SSL_CLIENT_CERT $ssl_client_cert;
    }
    } 


# Browser
 Have the CA above, issue a personal x509 to you and install it into your browser.

# TODO
 * Fix, automatic SSL_CLIENT_M_SERIAL, so that the first validated login adds it to the table_mapping.
 * Fix, add profile meta box, to allow to choose from certs, and add it to the profile-list, when you are an admin.
 * Fix, user-permissions in authenticate-plugin.
 * Fix, a lot of fixes, 
 * There is a RfC change, where in client_dn is changed from ',' to '/'

