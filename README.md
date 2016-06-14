# Socks5 proxy

## Intro

### Illustrate

```
+------------+            +--------------+          
| local app  |  <=======> | proxy client | <#######
+------------+            +--------------+        #
                                                  #
                                                  #
                                                  # encrypted data(ssl)
                                                  #
                                                  #
+-------------+            +--------------+       #
| target host |  <=======> | proxy server |  <#####
+-------------+            +--------------+         
```

1.  `proxy client` is running at your local computer.

    It receive your app (like a browser) request, encrypt the data,
    send to `proxy server`

2.  `proxy server` receive the request from `proxy client`,
    decrypt it, and sent to the target host.

3.  `proxy server` got the response from target host, then encrypt response,
    send back to `proxy client`.

4.  `proxy client` decrypt response received from `proxy server`,
    and send to local app.

5.  the circle done.


## Usage

### Server side

1.  `cp config.cfg.example config.cfg`,

	#### config.cfg
	
	*	`openssl genrsa -out privkey.pem 2048`
	*	`openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095`
	*	server.	Server ip
	*	server_port.	Default 7070
	*	local.	Client ip, default 127.0.0.1
	*	local_port.	Defalut 1080
	*	certfile. 	Default cacert.pem
	*	keyfile.	Defalut privkey.pem

2.	`python server.py`


### Local side

1.	use same of server config file

2.  `python client.py`

3. Done

Now, you can set your apps (e.g. Browser) Using socks5 proxy.

IP = `127.0.0.1`
PORT = `1080`  (if not changed in the config.cfg)
