Contributing to Coldwire project is simple, and is no different than any other Free and Open-Source project: 

Simply fork the repo, hack on the code, and do a pull request!

**However**, some specific parts of **Coldwire** require *careful* thought before contributing changes


## Protocol improvements and or adjustments
Before hacking on our codebase to support a new protocol feature, or to improve an existing one.
Coldwire depends on 2 seperate protocols: `Coldwire protocol`, and the `Strandlock protocol`

you *should* first read the related protocol specification, and modify it to reflect what you wish to be added / improved upon.

To summarize: Contributing major changes doesn't start with code, but with solid protocol improvements (that can be reasoned about), and that doesn't decrease our security posture (considering our threat model).


## `browsers_headers.json`
Before adding new entry, or modifying an existing one, please note that the *order* of the headers matters!
**Do not** trust Developer tools on whatever browser you're using. The ordering of headers in a browser are not in the order that they are sent on the wire. Failure to do so, would actually create an even uniquer fingerprint of our users.

Additionally, all headers names must be lowercase for interoperability with HTTP/2

A very important note, is to **never** include any headers that may indicate to a server you're intending to receive compressed (gzip, etc) response!.

Do not misunderstand, *include* the header (i.e. accept-encoding), but do not put in it actual encoding names. 

Instead, Spam "Coldwire" until the string reaches the same length of the intended "accept-encoding". Truncate "Coldwire" string as needed.

Another important note, is to put the headers in the **exact** order, that the browser in question sends them in. Again, **do not** rely on Dev tools for this.

And lastly, please do not contribute obsecure browsers headers! Keep all additions to be popular, mainstream browsers.


## Features that **will never be added**:
Here are some features that we have decided against implementing after thoughtful consideration, as they overcomplicate the protocol, and increase the attack-surface in general:
- Media parsing or sending in any of its forms (images, videos, SVGs, etc)
- Text formating or markup languages support (rich text formating, etc.)
- Multi-device support for the same account.
- Open/Public groups
- Voice, and video calls.
- Voice messages
- Compression support
- Metadata-rich features (avatars, vanity server-side usernames, bios, delievery receipts, read receipts, online status, last seen status, user-created server authentication passwords)
- Account recovery
- Persistent chat history
- Any "convenience" features that could impact security and or privacy (clickable URLs, keyboard hotkeys, keyboard shortscuts beyond the basic CTRL-C CTRL-V) 
