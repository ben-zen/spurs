# spurs: kinda like bootstraps

Silly name for a DHCP client (a BOOTP client at heart) but it lets me slip `rs` in there, which matters.

My goal is to explore zerocopy parsing to take network bytes and convert them into structured inputs to a DHCP client.
Once I have the options necessary to complete DORA written, I'll move on to implementing the L4 components needed to
override standard OS UDP.

The second stage of this, after getting the parsing basics written, is to design the actual runtime environment of a
client. I'd like to build around async, with the option of paring this down to run on Core and Embassy as an embedded
dhcp client. For now, desktop client with a library that can be used for a server as at least the parsing is my goal.
