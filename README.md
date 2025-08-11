# Network Simulator

A visual network simulation tool that allows users to design, build, and simulate network topologies with packet transmission.

## Features

- **Create Network Topologies**: Add various network devices (Servers, Routers, Switches, Computers, Access Points, Firewalls)
- **Define Network Connections**: Connect devices with links to establish communication paths
- **Simulate Packet Transmission**: Create and send packets between devices with real-time animation
- **Analyze Network Traffic**: View packet details including protocol, status, and round-trip time
- **Save/Load Simulations**: Save your network topology and simulation state for later use

## Requirements

- Python 3.6+
- Required packages:
  - tkinter
  - PIL (Pillow)
  - networkx
  - matplotlib

## Installation

1. Clone this repository or download the source code
2. Install the required packages:

```bash
pip install pillow networkx matplotlib
```

3. Make sure you have the `icons` folder containing the following icons:
   - server.png
   - switch.png
   - access_point.png
   - router.png
   - computer.png
   - firewall.png
   - packet.png

## Usage

Run the application:

```bash
python NetSim.py
```

### Creating a Network Topology

1. Click "Add Device" and select a device type
2. Devices can be dragged to position them anywhere on the canvas
3. Select two devices and click "Add Link" to connect them

### Simulating Network Traffic

1. Click "Create New Packet" to create a new packet
2. Select the source device, destination device, protocol, and speed
3. Click "Start Simulation" to begin packet transmission
4. View packet details in the analysis panel on the right

### Managing Your Network

- Use "Remove Device" to delete a device from the network
- Use "Remove Link" to disconnect two devices
- Use "Edit Device" to modify device properties
- Use "Save Simulation" to save your current network state
- Use "Load Simulation" to restore a previously saved network

## License

This project is available for use under the MIT license.

## Contact

For questions or feedback, please contact [M.Abdelaz17947@student.aast.edu] 