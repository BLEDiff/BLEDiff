# BLEDiff

This repository contains the open source implementation of BLEDiff, an automated, scalable, property-agnostic, and black-box protocol noncompliance checking framework for Bluetooth Low Energy (BLE) devices.

## System requirements  

- Ubuntu 18.04 machine (tested OS)  
- Python 2.7  
- nRF52480 dongle  

## Setup

### Setup environment

```bash
sudo chmod +x ./setup.sh
sudo ./setup.sh
cd fsm_inference_module/ble_controller/bluetooth/smp_server/
/usr/bin/python2.7 setup.py build
sudo /usr/bin/python2.7 setup.py install
mkdir -p ~/.local/lib/python2.7/site-packages/
cp dist/BLESMPServer-1.0.1-py2.7-linux-x86_64.egg ~/.local/lib/python2.7/site-packages
cd ../../
```

### Setup nRF52480

- Install nRF Connect for Desktop from [Nordic website](https://www.nordicsemi.com/Products/Development-tools/nrf-connect-for-desktop)
- You will need to write the provided hex files to the nRF5280 dongle. You can do this on windows or ubuntu. Windows is more preferable.
- To do this on ubuntu, run the nRF connect in sudo mode and add --no-sandbox flag
- Run the Programmer app from nRF connect
- Connect nRF52480 in DFU mode and write the two files from `nRF52480_hex_files/`
- After writing the hex files, remove the device from workstation and reconnect it.
- To test the Android device, you will need to install the nRF Connect for Mobile app on your device.  

### Setup configurations

- If the device under test uses static address, change "SlaveAddress" and "SlaveAddressType" at `fsm_inference_module/ble_controller/addr_config.json` file.  
- Change device properties at `fsm_inference_module/statelearner/src/ble.properties` file.  

### Device specific changes

- Add another switch case in `fsm_inference_module/statelearner/src/main/java/ble/statelearner/ble/devices/Device_SUL_Factory.java` and implement the corresponding file replicating `fsm_inference_module/statelearner/src/main/java/ble/statelearner/ble/devices/Device_SUL_Factory.java`.  
- Implement the reset and device interaction routines in `fsm_inference_module/device_controller/controller.py` following nexus6 case.  

## Run FSM Inference Module

- Run the BLEController:  

```bash
cd fsm_inference_module/ble_controller/
sudo /usr/bin/python2.7 ble_central.py
```

- Run the device controller:  

```bash
cd fsm_inference_module/device_controller/
sudo /usr/bin/python2.7 controller.py l <device>
```

- Compile and run the statelearner:  

```bash
cd fsm_inference_module/statelearner/
mvn package
sudo java -jar target/stateLearner-0.0.1-SNAPSHOT.jar src/ble.properties
```

## Citation

```
@INPROCEEDINGS {blediff,
  author = {I. Karim and A. Ishtiaq and S. Hussain and E. Bertino},
  booktitle = {2023 2023 IEEE Symposium on Security and Privacy (SP) (SP)},
  title = {BLEDiff : Scalable and Property-Agnostic Noncompliance Checking for BLE Implementations},
  year = {2023},
  volume = {},
  issn = {},
  pages = {1082-1100},
  abstract = {In this work, we develop an automated, scalable, property-agnostic, and black-box protocol noncompliance checking framework called BLEDiff that can analyze and uncover noncompliant behavior in the Bluetooth Low Energy (BLE) protocol implementations. To overcome the enormous manual effort of extracting BLE protocol reference behavioral abstraction and security properties from a large and complex BLE specification, BLEDiff takes advantage of having access to multiple BLE devices and leverages the concept of differential testing to automatically identify deviant noncompliant behavior. In this regard, BLEDiff first automatically extracts the protocol FSM of a BLE implementation using the active automata learning approach. To improve the scalability of active automata learning for the large and complex BLE protocol, BLEDiff explores the idea of using a divide and conquer approach. BLEDiff essentially divides the BLE protocol into multiple sub-protocols, identifies their dependencies and extracts the FSM of each sub-protocol separately, and finally composes them to create the large protocol FSM. These FSMs are then pair-wise tested to automatically identify diverse deviations. We evaluate BLEDiff with 25 different commercial devices and demonstrate it can uncover 13 different deviant behaviors with 10 exploitable attacks.},
  keywords = {bluetooth-low-energy;noncompliance-checking;implementation-security},
  doi = {10.1109/SP46215.2023.00062},
  url = {https://doi.ieeecomputersociety.org/10.1109/SP46215.2023.00062},
  publisher = {IEEE Computer Society},
  address = {Los Alamitos, CA, USA},
  month = {may}
}
```

## Acknowledgement

We acknowledge [LearnLib](https://learnlib.de/) for the active automata learning framework and [SweynTooth](https://asset-group.github.io/disclosures/sweyntooth/) for the implementation of BLE central. 



