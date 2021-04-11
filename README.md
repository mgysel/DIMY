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
python3 -m pip install wheel
python3 -m pip install -r requirements.txt
```

If for some weird reason you want everything installed...

```bash
python3 -m pip install --upgrade --user pip wheel
python3 -m pip install --user -r requirements.txt
```

## Run

Can `chmod` DIMY.py so that it's executable by you or just run the below.

```bash
python3 DIMY.py
```
