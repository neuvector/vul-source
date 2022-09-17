# Running Tests

Running the tests in a Bionic LXD container makes it easier to run both Python
2.7 and 3.6 and doesn't pollute your local python environment.

Install the required packages,

```bash
sudo apt install python python3 python-mock python3-mock python-pytest python3-pytest python-launchpadlib python3-launchpadlib libopenscap8 python-apt python3-apt python-coverage python3-coverage python-yaml
```

Clone the required repos,

```bash
git clone git://git.launchpad.net/ubuntu-cve-tracker && git clone git://git.launchpad.net/ubuntu-qa-tools
```

Grab the USN database,

```bash
cd ~/ubuntu-cve-tracker
~/ubuntu-cve-tracker/scripts/fetch-db database.json.bz2
```

Add the scripts to your PYTHONPATH,

```bash
vim ~/.bashrc
export PYTHONPATH="$PYTHONPATH:$HOME/ubuntu-qa-tools/common/:$HOME/ubuntu-cve-tracker/scripts/"
source ~/.bashrc
```

Run the tests,

```bash
python-coverage run -a -m pytest test/
python3-coverage run -a -m pytest test/
```

View coverage results,

```bash
python-coverage report
python3-coverage report
```
