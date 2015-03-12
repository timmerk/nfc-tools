# nfc-tools development site #
This project intent to provide useful NFC tools based on libnfc, the Open Source Near Field Communication (NFC) Library.

nfc-tools is not a toolkit itself, it just provide some software components that are build on top of libnfc.

The repository of this project hosts some experimental tools (libraries, application, etc.) before it become enough mature to be hosted in a dedicated project page.

If you are new to _libnfc_, you should browse the nfc-tools wiki[¹] to collect useful information and have a look to our forum[²].

# Requirements #
  * [libnfc](https://libnfc.googlecode.com): the public platform independent Near Field Communication (NFC) library
# Spin-off components #
Those components have now their own project page.
<br>Depending on your needs, you may find here what you are looking for:<br>
<h2>Libraries</h2>
<ul><li><a href='https://libfreefare.googlecode.com'>libfreefare</a>: a library for high level manipulation of MIFARE tags<br>
</li><li><a href='https://libllcp.googlecode.com'>libllcp</a>: a library implementing NFC Logical Link Control Protocol (LLCP)<br>
<h2>Drivers</h2>
</li><li><a href='https://ifdnfc.googlecode.com'>ifdnfc</a>: a PC/SC IFD Handler<br>
<h2>Desktop</h2>
</li><li><a href='https://qnfcd.googlecode.com'>qnfcd</a>: a C++/Qt daemon that exposes NFC devices through D-Bus<br>
<h2>Security audit</h2>
</li><li><a href='https://mfoc.googlecode.com'>MFOC</a>: <i>Mifare Classic Offline Cracker</i> is a tool that can recover keys from Mifare Classic cards</li></ul>

<h1>Components in the incubator</h1>
These projects are looking for maintainers, some just need porting to latest libnfc API, some need more code writing...<br>
Feel free to post patches on issue tracker.<br>
<br>
<h2>Tools</h2>
<ul><li><a href='http://nfc-tools.org/index.php?title=Lsnfc'>lsnfc</a> is a simple command that lists tags which are in your NFC device field.</li></ul>

<h2>Personal authentication for computers</h2>
<ul><li><a href='http://nfc-tools.org/index.php?title=Pam_nfc'>pam_nfc</a>: a PAM (Pluggable Authentication Module) which allow to authenticate using NFC</li></ul>

<h2>Embedded</h2>
<ul><li><a href='http://nfc-tools.org/index.php?title=Nfc-eventd'>nfc-eventd</a>: a NFC monitor daemon which is able to launch modules (libraries) on action (tag inserted or removed)</li></ul>

<h2>Desktop applications</h2>
<ul><li><a href='http://nfc-tools.org/index.php?title=DeskNFC'>DeskNFC</a>: a KDE4 Graphical User Interface to handle NFC content on desktop-like computers (relies on <a href='nfcd.md'>NFCd</a>)<br>
<h1>Links</h1>
</li></ul><ul><li><code>[1]</code> <b>Official wiki</b>: <a href='http://nfc-tools.org/'>http://nfc-tools.org/</a>
</li><li><code>[2]</code> <b>Forum</b>: <a href='http://www.libnfc.org/community'>http://www.libnfc.org/community</a>