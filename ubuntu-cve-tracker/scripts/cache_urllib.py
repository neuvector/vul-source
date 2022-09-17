'''cacheurllib.py - Wrapper around urllib which provides a cache.

(c) 2005 Martin Pitt <martin.pitt@ubuntu.com>
    2012 Jamie Strandboge <jamie@canonical.com>: work around http://bugs.python.org/issue6631
'''
from __future__ import print_function

import atexit
import pickle
import sys
import os.path
if sys.version_info[0] == 3:
    from urllib.request import urlopen as real_urlopen
else:
    # Not Python 3 - today, it is most likely to be Python 2
    # But note that this might need an update when Python 4
    # might be around one day
    from urllib import urlopen as real_urlopen


try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

# URL -> string
_cache = {}

def load_cache(file):
    '''Load the cache from a file.

    Does not fail on error.'''

    global _cache
    try:
        _cache = pickle.load(open(file, 'rb'))
    except IOError:
        pass

def save_cache(file):
    '''Write the cache into a file.'''

    global _cache
    pickle.dump(_cache, open(file, 'wb'))

def set_cache(file):
    '''Call load_cache to load the cache and register an exit function to write
    back the cache at program exit.'''

    load_cache(file)
    atexit.register(save_cache, file)

def urlopen(url, *args):
    '''Wrapper around urllib.urlopen(), caches URL contents in memory.'''

    global _cache
    #print "DEBUG: cache_urllib::urlopen: url is '%s'" % url
    if url.startswith('./'):
        clean_url = url[2:]
        print("WARN: cache_urllib::urlopen: caller should not use deprecated relative url", file=sys.stderr)
        print("      '%s'. Using '%s' instead " % (url, clean_url), file=sys.stderr)
        print("      For more information, please see http://bugs.python.org/issue6631.", file=sys.stderr)
        url = clean_url
    # python3 urllib wants to have a url type - so use file if none
    # specified
    if "://" not in url:
        url = "file:///" + os.path.abspath(url)
    if url not in _cache:
        _cache[url] = real_urlopen(url, *args).read().decode()
    return StringIO(_cache[url])

if __name__ == '__main__':
    import hashlib
    import time

    def checkurl():
        sum = hashlib.md5()
        for l in urlopen('http://people.canonical.com/~pitti/ubuntu-cve.new/unfixed.html'):
            sum.update(l)
        print(sum.hexdigest())

    set_cache('/tmp/cache_urllib.py_test.cache')
    t0 = time.time()
    checkurl()
    t1 = time.time()
    checkurl()
    t2 = time.time()

    print("First call:", (t1-t0), "second call:", (t2-t1), file=sys.stderr)
