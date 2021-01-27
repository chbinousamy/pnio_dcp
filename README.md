# PNIO DCP

A simple library to send PNIO DCP (PROFINET Dynamic Configuration Protocol) requests and parse the corresponding responses.

## Installation

This package can be installed via `pip`.
It was tested with python 3.6, other python version might work as well.

If your pip is already set up to handle the Codewerk nexus server:
```
pip install pnio_dcp
```

Using a default installation of pip:
```
pip install pnio_dcp -i https://nexus.codewerk.de/nexus/repository/pypi-codewerk/simple -v --trusted-host nexus.codewerk.de
```

Installing from source code:
```
pip install <path to project root>
```

## Usage

Create a new DCP instance with
```
ip = 10.0.0.76
dcp = pnio_dcp.DCP(ip)
```
where the given IP address is the IP of the host machine in the network to use for DCP communication.

### Identify Request
Identify requests can be used to identify DCP devices in the network. 
The identified devices are always returned as pnio_dcp.Device objects.

To identify all devices in the network, use
```
identified_devices = dcp.identify_all()
```
This returns a list containing all devices found. If no devices where found, this list is empty.

To get more information about a specific device the MAC address `mac_address`, use
```
mac_address = "02:00:00:00:00:00"
device = dcp.identify(mac_address)
```

### Set Requests
Set requests can be used to change parameters of the device with the MAC address `mac_address`.

Use to following, to set its name of station to the given `new_name` (a string):  
```
new_name = "a-new-name"
dcp.set_name_of_station(mac_address, new_name)
```

Use `set_ip_address` to set the IP configuration of the device. 
You must provide the new configuration as list containing the new IP address as first element, the subnet mask as second element, and the router as third element.
```
ip_conf = ['10.0.0.31', '255.255.240.0', '10.0.0.1']
dcp.set_ip_address(mac_address, ip_conf)
```

### Get Requests
Get requests can be used to get information about the device with the MAC address `mac_address`.  
Two such requests are supported: use 
```
ip = dcp.get_ip_address(mac_address)
```
to get the IP address of the device (as string) and
```
name_of_station = dcp.get_name_of_station(mac_address)
```
to get its name of station.

### Reset Requests

The communication parameters of the device with the MAC address `mac_address` can be reset to the factory settings with
```
dcp.reset_to_factory(mac_address)
```
