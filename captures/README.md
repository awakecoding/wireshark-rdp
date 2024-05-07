# Sample RDP Wireshark capture files

Here is a collection of RDP decrypted capture files, showing various scenarios.

## RDP with NLA, Kerberos password authentication #1

[rdp-nla-kerberos-auth1.pcapng](rdp-nla-kerberos-auth1.pcapng)

* Username: Administrator@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP NLA with Kerberos

## RDP with NLA, Kerberos password authentication #2

[rdp-nla-kerberos-auth2.pcapng](rdp-nla-kerberos-auth2.pcapng)

* Username: IT-HELP\Administrator
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP NLA with Kerberos

## RDP with NLA, NTLM rejected by server #1

[rdp-nla-ntlm-rejected1.pcapng](rdp-nla-ntlm-rejected1.pcapng)

* Username: IT-HELP\Administrator
* Server: 10.10.0.10
* Authentication: RDP NLA with NTLM

The client connected using the IP address instead of the FQDN, causing an NTLM downgrade on a server configured to reject inbound NTLM.

## RDP with NLA, NTLM rejected by server #2

[rdp-nla-ntlm-rejected2.pcapng](rdp-nla-ntlm-rejected2.pcapng)

* Username: Administrator@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP NLA with Kerberos (password), followed by an NTLM downgrade

The client connected using the FQDN of the server and attempted Kerberos password-based authentication, but after entering the wrong password, the RDP client downgraded to NTLM which is then rejected by the server due to the user being a member of the Protected Users group in Active Directory.

## RDP with NLA, Kerberos smartcard authentication #1

[rdp-nla-smartcard-auth1.pcapng](rdp-nla-smartcard-auth1.pcapng)

* Username: Administrator@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP NLA with Kerberos (smartcard)

## RDP with NLA, Kerberos smartcard authentication #2

[rdp-nla-smartcard-auth2.pcapng](rdp-nla-smartcard-auth2.pcapng)

* Username: ProtectedUser@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP NLA with Kerberos (smartcard)

## RDP without NLA, smartcard authentication #1

[rdp-no-nla-smartcard-auth1.pcapng](rdp-no-nla-smartcard-auth1.pcapng)

* Username: ProtectedUser@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP without NLA (smartcard)

## RDP without NLA, accepted by server #1

[rdp-no-nla-accepted1.pcapng](rdp-no-nla-accepted1.pcapng)

* Username: Administrator@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP without NLA (password)

## RDP without NLA, rejected by server #1

[rdp-no-nla-rejected1.pcapng](rdp-no-nla-rejected1.pcapng)

* Username: Administrator@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP without NLA (password)

## RDP without TLS, accepted by server #1

[rdp-no-tls-accepted1.pcapng](rdp-no-tls-accepted1.pcapng)

* Username: Administrator@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP without NLA, without TLS (password)

## RDP Restricted Admin Mode, accepted by server #1

[rdp-restricted-admin-accepted1.pcapng](rdp-restricted-admin-accepted1.pcapng)

* Username: Administrator@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP with NLA + Restricted Admin Mode

## RDP Restricted Admin Mode, rejected by server #1

[rdp-restricted-admin-rejected1.pcapng](rdp-restricted-admin-rejected1.pcapng)

* Username: Administrator@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP with NLA + Restricted Admin Mode

## RDP Remote Credential Guard, accepted by server #1

[rdp-credential-guard-accepted1.pcapng](rdp-credential-guard-accepted1.pcapng)

* Username: Administrator@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP with NLA + Remote Credential Guard

## RDP Remote Credential Guard, rejected by server #1

[rdp-credential-guard-rejected1.pcapng](rdp-credential-guard-rejected1.pcapng)

* Username: Administrator@ad.it-help.ninja
* Server: IT-HELP-TEST.ad.it-help.ninja
* Authentication: RDP with NLA + Remote Credential Guard
