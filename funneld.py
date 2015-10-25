import os

import click
from twisted.conch import unix, avatar
from twisted.conch import checkers as conch_checkers
from twisted.conch.interfaces import IConchUser
from twisted.conch.openssh_compat import factory
from twisted.conch.ssh.userauth import SSHUserAuthServer
from twisted.conch.ssh import keys, session
from twisted.cred import portal, checkers, credentials
from twisted.internet import reactor, defer, endpoints, task
from zope.interface import implementer, implements
from twisted.cred.credentials import ISSHPrivateKey
from twisted.internet.error import CannotListenError

publicKey = os.environ.get('PUBLIC_KEY', 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAGEArzJx8OYOnJmzf4tfBEvLi8DVPrJ3/c9k2I/Az64fxjHf9imyRJbixtQhlH9lfNjUIx+4LmrJH5QNRsFporcHDKOTwTTYLh5KmRpslkYHRivcJSkbh/C+BR3utDS555mV')

privateKey = os.environ.get('PRIVATE_KEY', """-----BEGIN RSA PRIVATE KEY-----
MIIByAIBAAJhAK8ycfDmDpyZs3+LXwRLy4vA1T6yd/3PZNiPwM+uH8Yx3/YpskSW
4sbUIZR/ZXzY1CMfuC5qyR+UDUbBaaK3Bwyjk8E02C4eSpkabJZGB0Yr3CUpG4fw
vgUd7rQ0ueeZlQIBIwJgbh+1VZfr7WftK5lu7MHtqE1S1vPWZQYE3+VUn8yJADyb
Z4fsZaCrzW9lkIqXkE3GIY+ojdhZhkO1gbG0118sIgphwSWKRxK0mvh6ERxKqIt1
xJEJO74EykXZV4oNJ8sjAjEA3J9r2ZghVhGN6V8DnQrTk24Td0E8hU8AcP0FVP+8
PQm/g/aXf2QQkQT+omdHVEJrAjEAy0pL0EBH6EVS98evDCBtQw22OZT52qXlAwZ2
gyTriKFVoqjeEjt3SZKKqXHSApP/AjBLpF99zcJJZRq2abgYlf9lv1chkrWqDHUu
DZttmYJeEfiFBBavVYIF1dOlZT0G8jMCMBc7sOSZodFnAiryP+Qg9otSBjJ3bQML
pSTqy7c3a2AScC/YyOwkDaICHnnD3XyjMwIxALRzl0tQEKMXs6hH8ToUdlLROCrP
EhQ0wahUTCk1gKA4uPD6TMTChavbh4K63OvbKg==
-----END RSA PRIVATE KEY-----""")


class FunnelAvatar(unix.UnixConchUser, unix.SSHSessionForUnixConchUser):
    """
    An UnixConchUser Avatar that always binds to the funnel user.
    """
    def __init__(self, funnel_user):
        unix.UnixConchUser.__init__(self, funnel_user) # proxy to system user
        unix.SSHSessionForUnixConchUser.__init__(self, self)
        self.channelLookup.update({'session':session.SSHSession})


class FunnelAuthorizedKeysFiles(conch_checkers.UNIXAuthorizedKeysFiles):
    """
    An UNIXAuthorizedKeysFiles database that looks for key files in the
    home directory of the funnel user:

        /home/$funnel_user/.ssh/$login_user.pub
    """

    def __init__(self, funnel_user, **kwargs):
        conch_checkers.UNIXAuthorizedKeysFiles.__init__(self, **kwargs)
        self.funnel_user = funnel_user
        self.root = self.get_root()

    def get_root(self):
        '''get FilePath ssh home directory'''
        try:
            passwd = self._userdb.getpwnam(self.funnel_user)
        except KeyError as E:
            return conch_checkers.FilePath('/tmp')

        return conch_checkers.FilePath(passwd.pw_dir).child('.ssh')

    def getAuthorizedKeys(self, username):
        '''get the public key for username'''
        filename = username + ".pub"
        filepath = self.root.child(filename)
        if filepath.exists():
            parsedKey = self._parseKey(filepath.open().read())
            return [parsedKey]
        return []

    def addAuthorizedKey(self, username, pubkey):
        '''set the public key for a username'''
        print "adding key for", username
        filename = username + ".pub"
        filepath = self.root.child(filename)
        with open(filepath.path, "wb") as fobj:
            fobj.write(pubkey.blob())


@implementer(checkers.ICredentialsChecker)
class FunnelPubkeyAuth(conch_checkers.SSHPublicKeyChecker):
    """
    This SSHPublicKeyChecker will return valid any login request for
    any username not previously used, remembering the client's public
    key. Any subsequent logins using the same username will require
    the original public key.
    """

    def __init__(self, funnel_user):
        keydb = FunnelAuthorizedKeysFiles(funnel_user)
        conch_checkers.SSHPublicKeyChecker.__init__(self, keydb)

    def _addKey(self, pubKey, credentials):
        self._keydb.addAuthorizedKey(credentials.username, pubKey)

    def _checkKey(self, pubKey, credentials):
        keys = self._keydb.getAuthorizedKeys(credentials.username)
        if len(keys):
            if any(key == pubKey for key in keys):
                return pubKey
            raise conch_checkers.UnauthorizedLogin("Key not authorized")
        self._addKey(pubKey, credentials)
        return pubKey


class FunnelRealm:
    """
    Realm that returns FunnelAvatars bound to the funnel user.
    """
    implements(portal.IRealm)

    def __init__(self, funnel_user):
        self.funnel_user = funnel_user

    def requestAvatar(self, avatarId, mind, *interfaces):
        return IConchUser, FunnelAvatar(self.funnel_user), lambda: None


def makeFunnelFactory(funnel_user, keypair):
    r = FunnelRealm(funnel_user)
    f = factory.OpenSSHFactory()
    f.portal = portal.Portal(r, [FunnelPubkeyAuth(funnel_user)])
    f.privateKeys = {'ssh-rsa': keys.Key.fromString(data=keypair[0])}
    f.publicKeys = {'ssh-rsa': keys.Key.fromString(data=keypair[1])}
    f.services['ssh-userauth'] = SSHUserAuthServer
    f.startFactory()
    return f


def listening(conn):
    hostinfo = conn.getHost()
    print "listening on {}:{}...".format(hostinfo.host, hostinfo.port)
    # return deferred that never fires,
    # so task.ract doesn't kill the reactor
    return defer.Deferred()


def notListening(err, port):
    err.trap(CannotListenError)
    print "Could not listen on port {}, are you root?".format(port)


def funnel(_, ep, funnel_user, keypair):
    f = makeFunnelFactory(funnel_user, keypair)
    return ep.listen(f).addCallbacks(listening, notListening)


@click.command(help="An SSH service for funneling user logins through a single system user")
@click.option('--port', default=22, help='Port to listen on.')
@click.option('--key', default=privateKey, help='Server private key')
@click.option('--pubkey', default=publicKey, help='Server public key')
@click.argument('user')
def main(port, user, key, pubkey):
    ep = endpoints.TCP4ServerEndpoint(reactor, int(port))
    task.react(funnel, (ep, user, (key, pubkey)))
