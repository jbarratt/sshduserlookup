## sshduserlookup 

This is a small tool that helps with a specific/unusual situation of having multiple 'real' users sharing access to a single UNIX user account.

One example might be a website account. Instead of each developer having to log in as their own users, upload files, and ensure they get permissions exactly right each time, multiple developers may share a `domain.com` user account.

However, this fails badly in the forensics department, especially if 'something went wrong'. Knowing which key was used when helps flatten this ambiguity.

To make this work, in your `/etc/ssh/sshd_config` file, you need to have `LogLevel VERBOSE`. This makes `sshd` log key fingerprints with each siginin.

### Running

This must be run with root privs, as it must be able to read all user's authorized_keys files.
Ideally it would be launched from a process manager such as `systemd`.

Simply give it the path to the auth log:

    # sshduserlookup /var/log/auth.log

And when an ssh user login happens, it will

* check a local cache to see if the user is already known
* If not, read the authorized_keys file for that user and figure out which key represented the login
* Syslog the results to the `AUTH` facility in either case

### Building

Because this tool does user lookups, it must be compiled with cgo support and on the target platform.
An easy way to do this from any system capable of running docker is to use the `golang-builder` image from CenturyLink:

	$ docker run --rm -e CGO_ENABLED=true -e COMPRESS_BINARY=true -v $(pwd):/src centurylink/golang-builder

