# Edition for Development of A. Client for MySql using TLSClient and B. any Client using TLSClient
This is a development edition. Upgraded MySql and also using native TLS. A TLSCLient without openssl. All native crystal. Far from production.


## ONE
The content here is as follows

``(tree -L 2)``
```
── APPLICS
│   ├── MYSQL
│   ├── web1
│   ├── web2
│   └── web3
├── LIBS
│   ├── librfc8439
│   ├── mysql
│   ├── shared
│   └── tlsclient
└── README.md
```


#### mysql holds
1. mixed (local and remote)
2. localonly (local only. to tryout)
3. remoteomly (remote ony. to tryout)
   
#### LIBS holds
1. librfc8439 (source git but with extensions)
2. mysql
3. shared
4. tlsclient

### Build test applictions
#### Walk through *.yml
Before you can start building you must look into all shard.yml because there are dependencies using path like:

(one for each APPL/* and one for each LIBS/*)

```yml
dependencies:
  tlsclient:
    path: <your path to this folder>/LIBS/tlsclient
```
#### Build libraries
```
for each LIBS
 shards update
 crystal docs
```
#### Build applications
```
for each APPLIC
 shards update
 shards build
```

Then just try build one, with or without debug options, for mysql (application 'mixed' )

You can include debug trace for each library if you compile with -Dtrctls -Dtrcsql -Dtrcshared
```
<>APPLICS/MYSQL/mixed> shards update
<>APPLICS/MYSQL/mixed> shards build
<>APPLICS/MYSQL/mixed> shards build --debug
<>APPLICS/MYSQL/mixed> shards build --debug -Dtrcsql -Dtrcshared
```
#### Set up MySql server to accept tls

Edit `/opt/homebrew/etc/my.cnf` to hold

```
# Default Homebrew MySQL server config
[mysqld]
# Only allow connections from localhost
# bind-address = 0.0.0.0 -->
# mysqlx-bind-address = 127.0.0.1
# Allow tls connection
ssl_ca=ca.pem
ssl_cert=server-cert.pem
ssl_key=server-key.pem
tls_version=TLSv1.2,TLSv1.3
require_secure_transport=ON

```
and run it with proper parameters
```
<>APPLICS/MYSQL/mixed> ./bin/mixed "url to database" "sql statement"
<>APPLICS/MYSQL/mixed> ./bin/mixed 7 # precompiled test number 7

```

Example  
```
<>APPLICS/MYSQL/mixed> ./bin/mixed "mysql://root:___@localhost/information_schema" "SELECT table_name FROM columns"
```

### More to do
There are some unresolved issues

1. APPLIC/web1: several web sites are hard to set up to a proper connection. This application 'APPLIC/web1' and the next 'APPLIC/MYSQL/mixed' use the same LIBS/tlsclient. 'APPLIC/MYSQL/mixed' works fine using tls but 'APPLIC/web1' struggles
2. APPLIC/MYSQL/mixed: two use case are not verified 
3. Running mysql through firewall/proxy and tls is not tested. 

   
Besides that there sevaral points to work on
1. Comments in general
2. Optimize LIBS/shared/*.cr to utilize hardware around crypto functions
3. This edition is build on MacOs Sequoia 15.3.2 (24D81) and Crystal 1.14.0 (2024-10-09)
4. No windows or bigendian is verified
5. Raise is not clever used at the moment
6. Extend the `spec` folder


### Tools

#### Source examin

> crystal tool unreachable src/mysql.cr
> 
> crystal tool hierarchy  src/web1.cr -e TLSClient
>
> crystal tool dependencies src/mysql.cr

#### CSV to 'everything'

https://tableconvert.com/csv-to-html

#### Analyze ASN.1 things

https://sandbox.swedenconnect.se/cap/asn1

## TWO Edition
## docs

The /docs content are not updated. `crystal docs` is not useable on MacOS at the moment.
## progress
Spent a lot of time on WEB using TLS. This implementation is using a limited set of variants on `Cryptographic Negotiation` from RFC 8446 4.1.1
https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.1

This is probaly the reason `alerts` like 'handshake_failure','unrecognized_name', 'protocol_version', 'internal_error'. 

### mysql (LIBS)
The classes `MySql::BRIDGE` , `MySql::Connection` and `MySql::SQLResponceReader` are just cleaned. And one read changed to read_filly. Look into results further down.

I have been able to contact an sql-client and sql-server on the same network LAN only. I have no access to a foreign sql-sever which might be configured differently.

### shared (LIBS)
`Module Xcrypt` cleaned too

### tlsclient (LIBS)
`TLSClient::Client` rewritten!
`TLSClient::ClientHelloMessage` cleaned
`TLSClient::ServerHelloMessage` revised around extensions
`TLSClient::Types` revised

### (APPLICS)
`web1/src/wbe1.cr` major enhanced. 

Simple web scraping in order to retrieve the first HTTP responce header and html. Just to evaluate the implemenation of TLS. 

### Result of 20 sites

1. 7 answered with `HTTP/1.1 200 OK` or others like 301,302,421 but with a proper html body
2. 6 answered with 'handshake_failure' 
3. Mix of 'unrecognized_name', 'protocol_version', 'internal_error' (NASA). There is no more information from the alert descibing the source of error. In state State=WAIT_SH (ServerHello)
4. One error in server treatment of messages. Detected. The same error found by other client (a go implementation). Site was 'sv-se.facebook.com'
5. Failing at 'www.polisen.se' decrypt error detetced. Probably this code.
The sent message clienthello and received serverhello message holds attribute that should be evaluated in order to continue in a proper way. There is no such checks today. Good testsite.


## Next step

For the record I think many RFC documents are very outdated, outmoded and unfashionable especilally on communication specification. Anytning new is named as an extension!. And versions is mess. In normal Business Application items and messages are removed, changed or added and version applied on that and changed rules. No one talks about extension. What about some Mathematics like `Category theory`

```
'Category theory' is a high-level, foundational branch of mathematics that formalizes mathematical structure by focusing on relationships—called morphisms or arrows—between objects, rather than the internal elements of those objects
```

I use to think a la

1. Types.
2. Shared attributes with type
3. Messages with (shared) attibutes and occurence (optional, 1 , [1,n]). 
4. Proper definitions and categorisation on package containing an hdr and payload.
5. State machine. Total. Complete. Not limitid to what can be descibed as TTY. Poor.
6. Conditions on what to accept and produce in each state.
7. Algorithms. Selfcontained for verification purposes
   
### next

There is a scetion 9.2. Mandatory-to-Implement Extensions https://datatracker.ietf.org/doc/html/rfc8446#section-9.2 I will look into a little further.




I will try to find out why the sessions is terminated in the state WAIT_SH (Point 2 and 3 above). There are some attributes in `ClientHelloMessage` in order to get a `ServerHelloMessage`. Like 'cipher_suites',  extensions.server_name, extensions.supported_groups, extensions.signature_algorithms, extensions.pre_shared_key, extensions.supported_versions.