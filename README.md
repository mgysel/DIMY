# DIMY - Did I Meet You

## Project Description
DIMY is a privacy-preserving contact tracing application that generates and shares ephemeral identifiers using Shamir’s Secret Sharing and Elliptic Curve Diffie-Hellman, and stores and checks COVID-positive contacts in bloom filters on Hyperledger. An in-depth discussion of the project can be found in `DIMY Final Report.pdf` and `DIMY Final Presentation.pdf`, and a demo video can be found below.

### Demo Video
[<img src="https://img.youtube.com/vi/zEjG_Cpm1y0/hqdefault.jpg" width="900" height="450"
/>](https://www.youtube.com/embed/zEjG_Cpm1y0)

## Requirements

- Python 3 (assuming 3.6+)
- Python PIP

## How to Install

Assuming a Debian-based system and the user is operating from the directory that this file is located in.\
Alternatives include installing in virtual environment (in which case the `--user` flag is not needed). Like so:

```bash
sudo apt-get install python3-venv
python3 -m venv ./venv
source ./venv/bin/activate
python3 -m pip install --upgrade pip wheel
python3 -m pip install -r ./requirements.txt
```

If for some weird reason you want everything installed in your own user profile...

```bash
python3 -m pip install --upgrade --user pip wheel
python3 -m pip install --user -r ./requirements.txt
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

### Clients

Copy the DIMY.py file to each device you want to act as a client.

You can also `chmod` DIMY.py (and server.py) so that it's executable by you or just run the below.

```bash
python3 ./DIMY.py
```

Note that if you intend to use the raspberry pi as another client and you are connecting the client to the raspberry pi via the raspberry pi's network, you can comment out `server.sendto(share_bytes, ('<broadcast>', 37025))` and uncomment the line directly beneath it (`# server.sendto(share_bytes, ('192.168.4.255', 37025))`). This should result in the code looking like:

```python
# server.sendto(share_bytes, ('<broadcast>', 37025))
server.sendto(share_bytes, ('192.168.4.255', 37025))
```

### Extension: Backend Server

Don't forget to run the server too. The server currently assumes that it will be run on the same system that DIMY.py will. If running on a different device, change `server_url` in DIMY.py to the IPv4 address that server.py is running on. Also make sure the server_url in DIMY.py and server.py port numbers are consistent so that the computer or Raspberry Pi can communicate with the server.

```bash
python3 ./server/server.py
```
