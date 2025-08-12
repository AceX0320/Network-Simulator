# NetSim - Network Simulator

NetSim is a comprehensive, GUI-based network topology simulator that allows users to design, visualize, and simulate computer networks with realistic packet transmission, protocol handling, and network analysis capabilities.

##  Features

###  Network Topology Design
- **Visual Network Builder**: Drag-and-drop interface for creating network topologies
- **Device Types**: Support for Servers, Routers, Switches, Access Points, Computers, and Firewalls
- **Custom Device Properties**: Configure IP addresses, MAC addresses, and device-specific settings
- **Interactive Positioning**: Click and drag devices to arrange your network layout

###  Protocol Simulation
- **Multiple Protocols**: TCP, UDP, and ICMP support
- **TCP Handshake**: Complete SYN → SYN-ACK → ACK → DATA sequence simulation
- **Packet Animation**: Real-time visual packet transmission across network paths
- **Path Finding**: Automatic shortest-path routing using advanced graph algorithms

###  Link Management
- **Configurable Link Properties**:
  - Delay (milliseconds)
  - Loss rate (0-1 probability)
  - Bandwidth (Mbps)
  - Protocol assignment
- **Real-time Link Editing**: Modify link properties during simulation
- **Visual Link Representation**: Color-coded connections with protocol labels

###  Network Tools
- **Ping Tool**: ICMP echo simulation with RTT measurement
- **Traceroute**: Hop-by-hop path visualization and timing
- **Packet Sender**: Custom packet creation and transmission
- **Real-time Analysis**: Live packet capture and inspection

###  Analysis & Monitoring
- **Packet Analyzer**: Real-time packet capture similar to Wireshark
- **Performance Metrics**: RTT measurement, packet status tracking
- **Transmission History**: Complete log of all network activity
- **Status Monitoring**: Real-time simulation status updates

###  Persistence & Themes
- **Save/Load Simulations**: Complete network state preservation in JSON format
- **Dark/Light Themes**: Toggle between professional theme options
- **Configuration Export**: Share network designs with others

##  Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Required Dependencies
```bash
pip install tkinter pillow networkx matplotlib ttkthemes
```

### Clone Repository
```bash
git clone https://github.com/yourusername/netsim.git
cd netsim
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Setup Icons (Optional but Recommended)
Create an `Icons` folder in the project directory and add the following PNG files (40x40 pixels recommended):
- `Server.png`
- `Switch.png` 
- `Access_Point.png`
- `Router.png`
- `Computer.png`
- `Firewall.png`
- `Package.png` (for packet animation)

**Note**: The simulator will work without icons using fallback circle representations.

##  Usage

### Starting the Simulator
```bash
python NetSim.py
```

### Basic Workflow

#### 1. Design Your Network
1. **Add Devices**: Click "Add Device" and specify name, IP address, and device type
2. **Position Devices**: Drag devices to arrange your network layout
3. **Create Links**: Click "Add Link" and specify endpoints and protocol
4. **Configure Links**: Use "Edit Link" to set delay, bandwidth, and loss rates

#### 2. Simulate Network Traffic
1. **Send Packets**: Use "Send Packet" to create custom network traffic
2. **Use Network Tools**: 
   - **Ping**: Test connectivity and measure RTT
   - **Traceroute**: Visualize packet paths through your network
3. **Monitor Traffic**: Watch real-time packet animation and analysis

#### 3. Analyze Performance
1. **Packet Analyzer**: View captured packets in the right panel
2. **Performance Metrics**: Monitor RTT, packet loss, and transmission status
3. **Export Results**: Save simulation data for later analysis

### Menu Options

#### File Menu
- **Save Simulation**: Export complete network state to JSON
- **Load Simulation**: Import previously saved simulations
- **Exit**: Close the application

#### Settings Menu
- **Simulation Settings**: Configure global loss rates and timeout values

#### View Menu
- **Toggle Dark Mode**: Switch between light and dark themes

#### Tools Menu
- **Ping (ICMP)**: Test network connectivity
- **Traceroute**: Trace packet paths
- **Send Packet**: Create custom network traffic

##  Architecture

### Core Components

#### Device Management
- **AdvancedDevice**: Represents network devices with IP/MAC addresses
- **DeviceType**: Enumeration of supported device types
- **Auto-MAC Generation**: Automatic MAC address assignment

#### Packet System
- **NetworkPacket**: Comprehensive packet representation with timing
- **PacketType**: Support for different packet types (DATA, SYN, ACK, etc.)
- **Animation Engine**: Smooth packet movement visualization

#### Network Analysis
- **PacketAnalyzer**: Real-time packet capture and analysis
- **Performance Metrics**: RTT calculation and status tracking
- **Export Capabilities**: JSON-based data persistence

#### Topology Management
- **NetworkX Integration**: Graph-based topology representation
- **Path Finding**: Shortest-path algorithms for packet routing
- **Dynamic Updates**: Real-time topology modification support

##  Configuration

### Default Link Properties
```python
LINK_DEFAULTS = {
    'delay_ms': 10,        # Link delay in milliseconds
    'loss_rate': 0.0,      # Packet loss probability (0-1)
    'bandwidth_mbps': 100, # Link bandwidth in Mbps
}
```

### Simulation Settings
- **Loss Rate**: Global packet loss probability
- **RTO**: Retransmission timeout in milliseconds
- **Animation Speed**: Packet movement speed multiplier

##  Use Cases

### Educational
- **Network Protocol Learning**: Visualize TCP handshakes and packet flow
- **Topology Design**: Practice network architecture concepts
- **Troubleshooting Training**: Learn network diagnostic techniques

### Professional
- **Network Planning**: Prototype network designs before implementation
- **Performance Analysis**: Model network behavior under different conditions
- **Documentation**: Create visual network documentation

### Research
- **Algorithm Testing**: Test routing and protocol algorithms
- **Performance Studies**: Analyze network performance metrics
- **Simulation Research**: Foundation for advanced network simulation

## 🐛 Known Limitations

- **Scalability**: Large networks (>50 devices) may impact performance
- **Protocol Depth**: Basic protocol implementation (no advanced TCP features)
- **Real-time Constraints**: Animation speed affects simulation accuracy
- **Single-threaded**: No parallel packet processing

##  Future Enhancements

- [ ] **Advanced Protocols**: OSPF, BGP routing protocol support
- [ ] **Network Security**: Firewall rules and security simulation
- [ ] **Performance Metrics**: Detailed throughput and latency analysis
- [ ] **Multi-threading**: Parallel packet processing
- [ ] **3D Visualization**: Three-dimensional network layouts
- [ ] **Real Hardware Interface**: Integration with physical network devices

##  Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Submit a pull request with a clear description

### Code Style
- Follow PEP 8 Python style guidelines
- Add docstrings to new classes and methods
- Include type hints where appropriate
- Write unit tests for new functionality

##  License

This project is licensed under the MIT License.

##  Acknowledgments

- **NetworkX**: Graph algorithms and data structures
- **Tkinter**: GUI framework and theming
- **PIL/Pillow**: Image processing for device icons
- **TTK Themes**: Enhanced visual styling

