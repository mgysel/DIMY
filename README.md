# DIMY - Did I Meet You

A simplified implementation of DIMY.

## Requirements

- Python 3
- Python PIP

## How to Install

Assuming a Debian-based system and user-based install. Alternatives include installing in virtual environment (in which case the `--user` flag is not needed). Like so:

```bash
sudo apt-get install python3-venv
python3 -m venv ./venv
source ./venv/bin/activate
python3 -m pip install --upgrade pip wheel
python3 -m pip install -r requirements.txt
```

If for some weird reason you want everything installed in your own user profile...

```bash
python3 -m pip install --upgrade --user pip wheel
python3 -m pip install --user -r requirements.txt
```

If for some weird reason `ecdsa` does not install... After installing `wheel` through `pip` (and removing a previously installed `ecdsa` through `python3 -m pip uninstall ecdsa`):

```bash
git clone "https://github.com/tlsfuzzer/python-ecdsa.git"
cd python-ecdsa
python3 ./setup.py build
python3 ./setup.py bdist_wheel
python3 -m pip install ./dist/ecdsa*.whl
```

## Run

You can also `chmod` DIMY.py so that it's executable by you or just run the below.

```bash
python3 DIMY.py
```

Don't forget to run the server too. The server currently assumes that it will be run on the same system that DIMY.py will. If running on a different device, change `server_url` in DIMY.py to the IPv4 address that server.py is running on.

```bash
python3 server/server.py
```
