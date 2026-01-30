### mysql/connection.cr condensed


## Readers
```
{plugin, auth_data} = InHandshakeV10
{plugin, auth_data}= InStateB
{plugin, auth_data}= InStateC
{ok?}=InStateD
{status, pub_key}=InStateE
```

## Writers
```
OutHandshakeResponse41TLS(capabilities, max_packet_size,character_set)
OutRequestPublicKeyAfter_sha256_password(1.to_u8)
OutHandshakeResponse41(capabilities, max_packet_size,character_set,username,def_plugin,catalog,plugin_name)
OutPasswordEnCoded(password)
OutRequestPublicKeyCommon(ResponceOn_caching_sha2_password.CachingSha2PasswordRequestPublicKey is 2)
SendRSAOAEPencoded(encode_password)
```


## Input Finite State Machine
It is plain CSV. One row for each state+event+condition. One row is 

``|optional one-read| something |optional one-write|``


(Use 'https://tableconvert.com/csv-to-ascii' in order to prettifiy csv below)
```
State, Reader, Condition, Writer, NextState
1, read_InHandshakeV10, mysql_options.want_tls, OutHandshakeResponse41TLS, P_tls
-, - , else, , A
A, , cond_1, OutRequestPublicKeyAfter_sha256_password, E
-, , else, OutHandshakeResponse41, B
B, anBRIDGE.read_packet, cond_1, OutRequestPublicKeyAfter_sha256_password, E 
-, -, cond_2, OutPasswordEnCoded, C
-, -, cond_3, , D
-, -, cond_4, OutRequestPublicKeyCommon, E
C, InStateC, cond_1, , D
-, - , cond_2, OutRequestPublicKeyCommon, E
-, - , cond_3, , END
-, - , cond_4, , END
-, - , cond_5, , END
D, InStateD, , , END
E, InStateE, cond_1 , SendRSAOAEPencoded, D
P_tls, , , create the tlsclient, Q_tls
Q_tls, , cond_1, not verified!, END
-, -, cond_2, OutHandshakeResponse41, R_tls
R_tls, InStateB, cond_1, send_password+read(InStateD), END
-, -, cond_2, OutPasswordEnCoded, END
-, -, cond_3, , D
-, -, cond_4, send_password, D
-, -, cond_5, , END
-, -, cond_6, not verified!, END
-, -, cond_7, , END
```

```
+-------+----------------------+------------------------+------------------------------------------+-----------+
| State | Reader               | Condition              | Writer                                   | NextState |
+-------+----------------------+------------------------+------------------------------------------+-----------+
| 1     | read_InHandshakeV10  | mysql_options.want_tls | OutHandshakeResponse41TLS                | P_tls     |
| -     | -                    | else                   |                                          | A         |
| A     |                      | cond_1                 | OutRequestPublicKeyAfter_sha256_password | E         |
| -     |                      | else                   | OutHandshakeResponse41                   | B         |
| B     | anBRIDGE.read_packet | cond_1                 | OutRequestPublicKeyAfter_sha256_password | E         |
| -     | -                    | cond_2                 | OutPasswordEnCoded                       | C         |
| -     | -                    | cond_3                 |                                          | D         |
| -     | -                    | cond_4                 | OutRequestPublicKeyCommon                | E         |
| C     | InStateC             | cond_1                 |                                          | D         |
| -     | -                    | cond_2                 | OutRequestPublicKeyCommon                | E         |
| -     | -                    | cond_3                 |                                          | END       |
| -     | -                    | cond_4                 |                                          | END       |
| -     | -                    | cond_5                 |                                          | END       |
| D     | InStateD             |                        |                                          | END       |
| E     | InStateE             | cond_1                 | SendRSAOAEPencoded                       | D         |
| P_tls |                      |                        | create the tlsclient                     | Q_tls     |
| Q_tls |                      | cond_1                 | not verified!                            | END       |
| -     | -                    | cond_2                 | OutHandshakeResponse41                   | R_tls     |
| R_tls | InStateB             | cond_1                 | send_password+read(InStateD)             | END       |
| -     | -                    | cond_2                 | OutPasswordEnCoded                       | END       |
| -     | -                    | cond_3                 |                                          | D         |
| -     | -                    | cond_4                 | send_password                            | D         |
| -     | -                    | cond_5                 |                                          | END       |
| -     | -                    | cond_6                 | not verified!                            | END       |
| -     | -                    | cond_7                 |                                          | END       |
+-------+----------------------+------------------------+------------------------------------------+-----------+
```