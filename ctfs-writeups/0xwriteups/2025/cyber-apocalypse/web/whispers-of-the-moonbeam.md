# Whispers of the Moonbeam

## Synopsis

Whispers of the Moonbeam is a very easy web challenge. Players will determine that terminal commands are system commands and execute command injection in order to get the flag.

### Skills Required

* Knowledge of Linux commands

### Skills Learned

* Performing command injection

## Solution

When we visit the site, we're greeted with a terminal application that accepts comamnds.

<figure><img src="../../../../../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

Typing commands like `gossip`, `observe` and `examine` will seemingly provide us linux command outputs, indicating it's running system commands. There's also a hint to use `;` for command injection.

<figure><img src="../../../../../.gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

We see the `flag.txt` on the `gossip` command, we can use command injection to `cat flag.txt`, using this payload:

```sh
observe; cat flag.txt
```

And we get the flag!

<figure><img src="../../../../../.gitbook/assets/image (110).png" alt=""><figcaption></figcaption></figure>

