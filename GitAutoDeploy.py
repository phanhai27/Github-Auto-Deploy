#!/usr/bin/env python

import json, sys, os, hmac
from socketserver import ThreadingMixIn
from http.server import SimpleHTTPRequestHandler, HTTPServer
from subprocess import call

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class GitAutoDeploy(SimpleHTTPRequestHandler):

    CONFIG_FILEPATH = './GitAutoDeploy.conf.json'
    config = None
    quiet = False
    daemon = False

    body = None
    branch = None
    urls = None

    secret = None

    @classmethod
    def getConfig(myClass):
        if(myClass.config == None):
            try:
                configString = open(myClass.CONFIG_FILEPATH).read()
            except:
                sys.exit('Could not load ' + myClass.CONFIG_FILEPATH + ' file')

            try:
                myClass.config = json.loads(configString)
            except:
                sys.exit(myClass.CONFIG_FILEPATH + ' file is not valid json')

            for repository in myClass.config['repositories']:
                if(not os.path.isdir(repository['path'])):
                    sys.exit('Directory ' + repository['path'] + ' not found')
                # Check for a repository with a local or a remote GIT_WORK_DIR
                if not os.path.isdir(os.path.join(repository['path'], '.git')) \
                   and not os.path.isdir(os.path.join(repository['path'], 'objects')):
                    sys.exit('Directory ' + repository['path'] + ' is not a Git repository')
        
        try:
            myClass.secret = myClass.config['secret']
        except:
            print('[WARNING] No secret key. Security mode is off. Not validating Github signature.')
        
        return myClass.config

    def do_POST(self):
        event = self.headers.get('X-Github-Event')
        if event == 'ping':
            if not self.quiet:
                print('Ping event received')
            self.respond(204)
            return
        if event != 'push':
            if not self.quiet:
                print('We only handle ping and push events')
            self.respond(304)
            return

        self.parseRequest() # to get body, branch and urls

        if self.secret is not None: # if security mode is on
            signature = self.headers.get("x-hub-signature-256", self.headers.get("x-hub-signature"))
            if signature is not None:
                if not validate_event(self.body, signature=signature, secret=self.secret):
                    self.respond(304)
                    return
            else:
                self.respond(304)
                return
        
        self.respond(204)

        for url in self.urls:
            paths = self.getMatchingPaths(url)
            for path in paths:
                self.fetch(path)
                self.deploy(path)
    
    def do_GET(self):
        self.send_error(404, "File Not Found {}".format(self.path))

    def parseRequest(self):
        length = int(self.headers.get('content-length'))
        self.body = self.rfile.read(length)
        payload = json.loads(self.body)
        self.branch = payload['ref']
        self.urls = [payload['repository']['url']]

    def getMatchingPaths(self, repoUrl):
        res = []
        config = self.getConfig()
        for repository in config['repositories']:
            if(repository['url'] == repoUrl):
                res.append(repository['path'])
        return res

    def respond(self, code):
        self.send_response(code)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    def fetch(self, path):
        if(not self.quiet):
            print("\nPost push request received")
            print('Updating ' + path)
        call(['cd "' + path + '" && git fetch'], shell=True)

    def deploy(self, path):
        config = self.getConfig()
        for repository in config['repositories']:
            if(repository['path'] == path):
                if 'deploy' in repository:
                    branch = None
                    if 'branch' in repository:
                        branch = repository['branch']

                    if branch is None or branch == self.branch:
                        if(not self.quiet):
                            print('Executing deploy command')
                        call(['cd "' + path + '" && ' + repository['deploy']], shell=True)
                        
                    elif not self.quiet:
                        print('Push to different branch (%s != %s), not deploying' % (branch, self.branch))
                break

def validate_event(payload: bytes, signature: str, secret: str):
    """Validate the signature of a webhook event."""
    # https://docs.github.com/en/developers/webhooks-and-events/securing-your-webhooks#validating-payloads-from-github
    sha256_signature_prefix = "sha256="
    sha1_signature_prefix = "sha1="
    if signature.startswith(sha256_signature_prefix):
        hmac_sig = hmac.new(
            secret.encode("UTF-8"), msg=payload, digestmod="sha256"
        ).hexdigest()
        calculated_sig = sha256_signature_prefix + hmac_sig
    elif signature.startswith(sha1_signature_prefix):
        hmac_sig = hmac.new(
            secret.encode("UTF-8"), msg=payload, digestmod="sha1"
        ).hexdigest()
        calculated_sig = sha1_signature_prefix + hmac_sig
    else:
        return False
    
    if not hmac.compare_digest(signature, calculated_sig):
        return False
    
    return True

def main():
    try:
        server = None
        for arg in sys.argv: 
            if(arg == '-d' or arg == '--daemon-mode'):
                GitAutoDeploy.daemon = True
                GitAutoDeploy.quiet = True
            if(arg == '-q' or arg == '--quiet'):
                GitAutoDeploy.quiet = True
                
        if(GitAutoDeploy.daemon):
            pid = os.fork()
            if(pid != 0):
                sys.exit()
            os.setsid()

        if(not GitAutoDeploy.quiet):
            print('Github Autodeploy Service v0.2 started')
        else:
            print('Github Autodeploy Service v 0.2 started in daemon mode')
        
        server = ThreadingHTTPServer(("", GitAutoDeploy.getConfig()['port']), GitAutoDeploy)
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit) as e:
        if(e): # wtf, why is this creating a new line?
            print(e, file=sys.stderr)

        if(not server is None):
            server.socket.close()

        if(not GitAutoDeploy.quiet):
            print('Goodbye')

if __name__ == '__main__':
     main()
