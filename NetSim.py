import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from PIL import Image, ImageTk
import networkx as nx
import random
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
from datetime import datetime
import json
import re
import collections
import itertools
from typing import Dict, List, Tuple, Optional

# Centralized defaults for link attributes
LINK_DEFAULTS: Dict[str, float] = {
    'delay_ms': 10,
    'loss_rate': 0.0,
    'bandwidth_mbps': 100,
}

class DeviceType:
    SERVER = "Server"
    SWITCH = "Switch"
    ACCESS_POINT = "Access-Point"
    ROUTER = "Router"
    COMPUTER = "Computer"
    FIREWALL = "Firewall"

# Class bt3ml represent le different types of devices bl names we el ip addresses
class AdvancedDevice:
    def __init__(self, name, ip_address, device_type):
        self.name = name
        self.ip_address = ip_address
        self.mac_address = self.generate_mac_address()
        self.device_type = device_type

    @staticmethod
    def generate_mac_address():
        return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])

    def to_dict(self):
        return {
            'name': self.name,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'device_type': self.device_type
        }

    @classmethod
    def from_dict(cls, data):
        device = cls(data['name'], data['ip_address'], data['device_type'])
        device.mac_address = data['mac_address']
        return device

_PACKET_ID = itertools.count(1)

class NetworkPacket:
    def __init__(self, source: str, destination: str, protocol: str, payload: str, speed: float = 1.0):
        """Represents a network packet in the simulator."""
        self.id: int = next(_PACKET_ID)
        self.source: str = source
        self.destination: str = destination
        self.protocol: str = protocol
        self.payload: str = payload
        self.timestamp: datetime = datetime.now()
        self.status: str = "Pending"
        self.path: List[str] = []
        self.current_position: int = 0
        self.speed: float = speed
        self.rtt: Optional[float] = None
        self.start_time: Optional[float] = None
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'source': self.source,
            'destination': self.destination,
            'protocol': self.protocol,
            'payload': self.payload,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'path': self.path,
            'current_position': self.current_position,
            'speed': self.speed,
            'rtt': self.rtt
        }
    
    @classmethod
    def from_dict(cls, data: Dict):
        packet = cls(
            source=data['source'],
            destination=data['destination'],
            protocol=data['protocol'],
            payload=data['payload'],
            speed=data['speed']
        )
        # Preserve ID if present (for replays)
        if 'id' in data:
            packet.id = int(data['id'])
        packet.timestamp = datetime.fromisoformat(data['timestamp'])
        packet.status = data['status']
        packet.path = data['path']
        packet.current_position = data['current_position']
        packet.rtt = data['rtt']
        return packet
    
    def start_transmission(self):
        self.start_time = time.time()

    def complete_transmission(self):
        if self.start_time:
            self.rtt = (time.time() - self.start_time) * 1000  # Convert to milliseconds

class PacketAnalyzer: #capture packets and analyses them
    def __init__(self):
        self.captured_packets = []
        self.current_simulation = None

    def capture_packet(self, packet):
        self.captured_packets.append(packet)

    def to_dict(self):
        return {
            'captured_packets': [packet.to_dict() for packet in self.captured_packets]
        }
    
    @classmethod
    def from_dict(cls, data):
        analyzer = cls()
        analyzer.captured_packets = [NetworkPacket.from_dict(packet_data) 
                                    for packet_data in data['captured_packets']]
        return analyzer
    
    def get_packet_details(self):
        details = []
        for packet in self.captured_packets:
            rtt_info = f"RTT: {packet.rtt:.2f}ms" if packet.rtt is not None else "RTT: N/A"
            details.append(
                f"Time: {packet.timestamp.strftime('%H:%M:%S')} | "
                f"Source: {packet.source} -> Destination: {packet.destination} | "
                f"Protocol: {packet.protocol} | Status: {packet.status} | "
                f"Speed: {packet.speed} | {rtt_info}"
            )
        return details

    def update_simulation_status(self, packet, status):
        packet.status = status
        if status == "In Progress":
            packet.start_transmission()
        elif status == "Completed":
            packet.complete_transmission()
# da el by load el GUI nfso
class AdvancedNetworkSimulator:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Net-Sim")
        self.root.geometry("1400x800")

        self.devices = {}
        self.network_topology = nx.Graph()
        self.device_icons = {}
        self.packet_icon = None
        self.packet_analyzer = PacketAnalyzer()
        self.selected_device = None
        self.offset_x = 0
        self.offset_y = 0
        self.simulation_active = False
        self.packet_objects: Dict[int, int] = {}
        self.node_positions: Dict[str, Tuple[float, float]] = {}
        # Theming
        self.dark_mode = False
        self.color_bg_light = "#FFFFFF"
        self.color_bg_dark = "#1E1E1E"
        self.color_text_light = "#000000"
        self.color_text_dark = "#E6E6E6"
        self.color_edge_light = "#808080"  # gray
        self.color_edge_dark = "#666666"
        self.color_highlight_light = "#0000FF"  # blue
        self.color_highlight_dark = "#00D1FF"
        # Simulation settings
        self.loss_rate = 0.0  # probability [0..1] of segment loss
        self.rto_ms = 800     # retransmission timeout in ms

        self.load_icons()
        self.create_menu()
        self.create_split_gui()
        self.apply_theme()
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Simulation", command=self.save_simulation)
        file_menu.add_command(label="Load Simulation", command=self.load_simulation)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)

        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Simulation Settings", command=self.open_simulation_settings)

        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Dark Mode", command=self.toggle_dark_mode)

        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Ping (ICMP)", command=self.open_ping_tool)
        tools_menu.add_command(label="Traceroute", command=self.open_traceroute_tool)
    #  da el m5ly el gui y2sm el window l 2
    def create_split_gui(self):
        
        self.main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        self.topology_frame = ttk.Frame(self.main_container)
        self.main_container.add(self.topology_frame, weight=50)
        
        self.analysis_frame = ttk.Frame(self.main_container)
        self.main_container.add(self.analysis_frame, weight=50)

        self.create_topology_panel()
        self.create_packet_analysis_panel()

    def create_topology_panel(self):
        topology_panel = ttk.LabelFrame(self.topology_frame, text="Network Topology")
        topology_panel.pack(fill="both", expand=True, padx=5, pady=5)

        self.topology_canvas = tk.Canvas(topology_panel, bg="white")
        self.topology_canvas.pack(fill="both", expand=True)

        toolbar = ttk.Frame(topology_panel)
        toolbar.pack(fill="x", padx=5, pady=5)

        ttk.Button(toolbar, text="Add Device", command=self.add_device).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Add Link", command=self.add_link).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Remove Link", command=self.remove_link).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Edit Link", command=self.edit_link).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Remove Device", command=self.remove_device).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Edit Device", command=self.edit_device).pack(side="left", padx=2)

        self.topology_canvas.bind("<Button-1>", self.on_click)
        self.topology_canvas.bind("<B1-Motion>", self.on_drag)
        

    # ===== Basic helpers and UI callbacks to ensure runtime readiness =====
    def current_colors(self) -> Dict[str, str]:
        """Return current theme color palette."""
        return {
            'bg': self.color_bg_dark if self.dark_mode else self.color_bg_light,
            'text': self.color_text_dark if self.dark_mode else self.color_text_light,
            'edge': self.color_edge_dark if self.dark_mode else self.color_edge_light,
            'hl': self.color_highlight_dark if self.dark_mode else self.color_highlight_light,
        }

    def apply_theme(self) -> None:
        """Apply theme to root and canvas."""
        colors = self.current_colors()
        try:
            self.root.configure(bg=colors['bg'])
        except Exception:
            pass
        if hasattr(self, 'topology_canvas') and self.topology_canvas:
            self.topology_canvas.configure(bg=colors['bg'])

    def load_icons(self) -> None:
        """Load icons if available; fallback gracefully to None."""
        try:
            # Optional: load icons from ./icons, but fallback gracefully
            self.device_icons = {
                DeviceType.SERVER: None,
                DeviceType.SWITCH: None,
                DeviceType.ACCESS_POINT: None,
                DeviceType.ROUTER: None,
                DeviceType.COMPUTER: None,
                DeviceType.FIREWALL: None,
            }
            self.packet_icon = None
        except Exception:
            self.device_icons = {}
            self.packet_icon = None

    def get_device_position(self, name: str) -> Tuple[float, float]:
        """Return device position, assigning a default grid position if absent."""
        pos = self.node_positions.get(name)
        if pos:
            return pos
        # default grid placement
        idx = list(self.devices.keys()).index(name) if name in self.devices else 0
        x = 100 + (idx % 8) * 120
        y = 100 + (idx // 8) * 120
        self.node_positions[name] = (x, y)
        return x, y

    def refresh_topology(self) -> None:
        """Redraw the entire topology (nodes and edges) with current theme."""
        if not hasattr(self, 'topology_canvas'):
            return
        self.topology_canvas.delete("all")
        colors = self.current_colors()

        # Draw edges
        for u, v in self.network_topology.edges():
            x1, y1 = self.get_device_position(u)
            x2, y2 = self.get_device_position(v)
            self.topology_canvas.create_line(x1, y1, x2, y2, fill=colors['edge'], tags=('edge',))

        # Draw nodes
        for name in self.network_topology.nodes():
            x, y = self.get_device_position(name)
            # Fallback circle
            r = 18
            self.topology_canvas.create_oval(x - r, y - r, x + r, y + r, fill=colors['bg'], outline=colors['text'], width=2, tags=(name,))
            self.topology_canvas.create_text(x, y + 28, text=name, fill=colors['text'], tags=(name,))

    def create_packet_analysis_panel(self) -> None:
        """Create a simple packet analyzer list panel."""
        panel = ttk.LabelFrame(self.analysis_frame, text="Packet Analyzer")
        panel.pack(fill="both", expand=True, padx=5, pady=5)
        self.packet_list = tk.Listbox(panel, height=20)
        self.packet_list.pack(fill="both", expand=True)

    def update_packet_list(self) -> None:
        """Refresh the packet list UI from analyzer state."""
        if not hasattr(self, 'packet_list'):
            return
        self.packet_list.delete(0, tk.END)
        for line in self.packet_analyzer.get_packet_details():
            self.packet_list.insert(tk.END, line)

    def open_simulation_settings(self) -> None:
        """Open a minimal dialog to update global simulation settings."""
        try:
            loss = simpledialog.askfloat("Simulation Settings", "Default loss rate (0..1):", initialvalue=self.loss_rate, minvalue=0.0, maxvalue=1.0)
            if loss is not None:
                self.loss_rate = float(loss)
            rto = simpledialog.askinteger("Simulation Settings", "RTO (ms):", initialvalue=self.rto_ms, minvalue=50, maxvalue=10000)
            if rto is not None:
                self.rto_ms = int(rto)
            messagebox.showinfo("Settings", "Simulation settings updated.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update settings: {e}")

    def open_ping_tool(self) -> None:
        """Minimal ping: record a synthetic ICMP packet and update analyzer UI."""
        if not self.devices:
            messagebox.showinfo("Ping", "Add devices first.")
            return
        src = simpledialog.askstring("Ping", "Source device name:")
        dst = simpledialog.askstring("Ping", "Destination device name:")
        if not src or not dst or src not in self.devices or dst not in self.devices:
            messagebox.showerror("Ping", "Invalid source/destination.")
            return
        # Determine path and total simulated RTT based on per-link delays
        try:
            path = nx.shortest_path(self.network_topology, src, dst)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            messagebox.showerror("Ping", "No path between selected nodes.")
            return

        total_one_way = 0
        for i in range(len(path) - 1):
            total_one_way += self.get_edge_delay(path[i], path[i+1])
        total_rtt = max(1, int(total_one_way) * 2)

        # Create packet and animate highlight along the path
        pkt = NetworkPacket(source=src, destination=dst, protocol="ICMP", payload="echo")
        pkt.path = path
        self.packet_analyzer.capture_packet(pkt)
        self.packet_analyzer.update_simulation_status(pkt, "In Progress")
        self.update_packet_list()

        def step(i: int):
            if i >= len(path):
                return
            self.highlight_packet_path(pkt, path[i])
            if i + 1 < len(path):
                delay = self.get_edge_delay(path[i], path[i+1])
            else:
                delay = 200
            self.root.after(max(1, delay), lambda: step(i + 1))

        # Start animation and schedule completion to set RTT
        step(1)
        def complete_ping():
            self.packet_analyzer.update_simulation_status(pkt, "Completed")
            # Ensure RTT reflects our simulated total
            pkt.rtt = float(total_rtt)
            self.update_packet_list()
        self.root.after(total_rtt, complete_ping)

    def get_edge_delay(self, u: str, v: str) -> int:
        data = self.network_topology.get_edge_data(u, v) or {}
        try:
            return int(data.get('delay_ms', LINK_DEFAULTS['delay_ms']))
        except Exception:
            return int(LINK_DEFAULTS['delay_ms'])

    def open_traceroute_tool(self) -> None:
        """Animate hop-by-hop path highlighting from source to destination."""
        if not self.devices or self.network_topology.number_of_edges() == 0:
            messagebox.showinfo("Traceroute", "Add devices and links first.")
            return
        src = simpledialog.askstring("Traceroute", "Source device name:")
        dst = simpledialog.askstring("Traceroute", "Destination device name:")
        if not src or not dst or src not in self.devices or dst not in self.devices:
            messagebox.showerror("Traceroute", "Invalid source/destination.")
            return
        try:
            path = nx.shortest_path(self.network_topology, src, dst)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            messagebox.showerror("Traceroute", "No path between selected nodes.")
            return

        # Use a temporary packet object to reuse highlight logic
        temp_pkt = NetworkPacket(source=src, destination=dst, protocol="TRACE", payload="")
        temp_pkt.path = path

        def step(i: int):
            if i >= len(path):
                return
            self.highlight_packet_path(temp_pkt, path[i])
            if i + 1 < len(path):
                delay = self.get_edge_delay(path[i], path[i+1])
            else:
                delay = 400
            self.root.after(max(1, delay), lambda: step(i + 1))

        step(1)

    # ===== Topology editing =====
    def add_device(self) -> None:
        name = simpledialog.askstring("Add Device", "Device name:")
        if not name:
            return
        if name in self.devices:
            messagebox.showerror("Error", "Device already exists.")
            return
        dtype = simpledialog.askstring("Add Device", f"Type ({', '.join([DeviceType.SERVER, DeviceType.SWITCH, DeviceType.ACCESS_POINT, DeviceType.ROUTER, DeviceType.COMPUTER, DeviceType.FIREWALL])}):", initialvalue=DeviceType.COMPUTER)
        ip = simpledialog.askstring("Add Device", "IP address:", initialvalue="192.168.1.1")
        if ip and not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            messagebox.showerror("Error", "Invalid IP address format.")
            return
        if not dtype or not ip:
            return
        dev = AdvancedDevice(name, ip, dtype)
        self.devices[name] = dev
        self.network_topology.add_node(name)
        self.get_device_position(name)
        self.refresh_topology()

    def remove_device(self) -> None:
        if not self.selected_device:
            messagebox.showinfo("Info", "Select a device first.")
            return
        name = self.selected_device
        if name in self.devices:
            del self.devices[name]
        if name in self.node_positions:
            del self.node_positions[name]
        if name in self.network_topology:
            self.network_topology.remove_node(name)
        self.selected_device = None
        self.refresh_topology()

    def add_link(self) -> None:
        a = simpledialog.askstring("Add Link", "Endpoint A:")
        b = simpledialog.askstring("Add Link", "Endpoint B:")
        if not a or not b or a not in self.devices or b not in self.devices or a == b:
            messagebox.showerror("Error", "Invalid endpoints.")
            return
        if self.network_topology.has_edge(a, b):
            messagebox.showinfo("Info", "Link already exists.")
            return
        self.network_topology.add_edge(a, b, **LINK_DEFAULTS)
        self.refresh_topology()

    def remove_link(self) -> None:
        a = simpledialog.askstring("Remove Link", "Endpoint A:")
        b = simpledialog.askstring("Remove Link", "Endpoint B:")
        if not a or not b:
            return
        if self.network_topology.has_edge(a, b):
            self.network_topology.remove_edge(a, b)
            self.refresh_topology()
        else:
            messagebox.showinfo("Info", "Link not found.")

    def edit_link(self) -> None:
        a = simpledialog.askstring("Edit Link", "Endpoint A:")
        b = simpledialog.askstring("Edit Link", "Endpoint B:")
        if not a or not b or not self.network_topology.has_edge(a, b):
            messagebox.showerror("Error", "Link not found.")
            return
        attrs = self.network_topology.get_edge_data(a, b) or {}
        try:
            delay = simpledialog.askinteger("Edit Link", "Delay (ms):", initialvalue=int(attrs.get('delay_ms', LINK_DEFAULTS['delay_ms'])), minvalue=0, maxvalue=10000)
            loss = simpledialog.askfloat("Edit Link", "Loss rate (0..1):", initialvalue=float(attrs.get('loss_rate', LINK_DEFAULTS['loss_rate'])), minvalue=0.0, maxvalue=1.0)
            bw = simpledialog.askinteger("Edit Link", "Bandwidth (Mbps):", initialvalue=int(attrs.get('bandwidth_mbps', LINK_DEFAULTS['bandwidth_mbps'])), minvalue=1, maxvalue=100000)
            if delay is not None:
                attrs['delay_ms'] = int(delay)
            if loss is not None:
                attrs['loss_rate'] = float(loss)
            if bw is not None:
                attrs['bandwidth_mbps'] = int(bw)
            self.network_topology[a][b].update(attrs)
            self.refresh_topology()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to edit link: {e}")

    # ===== Mouse handlers =====
    def on_click(self, event) -> None:
        # Select closest device by tag hit
        items = self.topology_canvas.find_withtag(tk.CURRENT)
        self.selected_device = None
        if items:
            tags = self.topology_canvas.gettags(items[0])
            for t in tags:
                if t in self.devices:
                    self.selected_device = t
                    break
        if self.selected_device:
            x, y = self.get_device_position(self.selected_device)
            self.offset_x = event.x - x
            self.offset_y = event.y - y

    def on_drag(self, event) -> None:
        if not self.selected_device:
            return
        new_x = event.x - self.offset_x
        new_y = event.y - self.offset_y
        self.node_positions[self.selected_device] = (new_x, new_y)
        self.refresh_topology()

    def edit_device(self):
        if not self.selected_device:
            messagebox.showinfo("Info", "Please select a device first.")
            return

        device = self.devices[self.selected_device]
        edit_window = tk.Toplevel(self.root)
        edit_window.title(f"Edit Device: {device.name}")
        edit_window.geometry("300x200")

        # IP Address
        ttk.Label(edit_window, text="IP Address:").pack(pady=5)
        ip_var = tk.StringVar(value=device.ip_address)
        ip_entry = ttk.Entry(edit_window, textvariable=ip_var)
        ip_entry.pack(pady=5)

        # MAC Address
        ttk.Label(edit_window, text="MAC Address:").pack(pady=5)
        mac_var = tk.StringVar(value=device.mac_address)
        mac_entry = ttk.Entry(edit_window, textvariable=mac_var)
        mac_entry.pack(pady=5)

        def validate_and_save():
            # Validate IP address
            ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
            if not ip_pattern.match(ip_var.get()):
                messagebox.showerror("Error", "Invalid IP address format")
                return

            # Validate MAC address
            mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
            if not mac_pattern.match(mac_var.get()):
                messagebox.showerror("Error", "Invalid MAC address format")
                return

            device.ip_address = ip_var.get()
            device.mac_address = mac_var.get()
            edit_window.destroy()
            self.refresh_topology()

        ttk.Button(edit_window, text="Save", command=validate_and_save).pack(pady=10)
    
    def save_simulation(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if not file_path:
            return

        # Serialize edges with attributes for persistence
        try:
            data = {
                'version': 1,
                'devices': [dev.to_dict() for dev in self.devices.values()],
                'edges': [
                    {
                        'u': u,
                        'v': v,
                        'attrs': {
                            'delay_ms': edata.get('delay_ms', LINK_DEFAULTS['delay_ms']),
                            'loss_rate': edata.get('loss_rate', LINK_DEFAULTS['loss_rate']),
                            'bandwidth_mbps': edata.get('bandwidth_mbps', LINK_DEFAULTS['bandwidth_mbps']),
                        }
                    }
                    for u, v, edata in self.network_topology.edges(data=True)
                ],
                'node_positions': self.node_positions,
                'settings': {
                    'dark_mode': self.dark_mode,
                    'loss_rate': self.loss_rate,
                    'rto_ms': self.rto_ms,
                },
                'analyzer': self.packet_analyzer.to_dict(),
            }

            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo("Success", "Simulation saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save simulation: {str(e)}")
    
    def load_simulation(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json")]
        )
        if not file_path:
            return
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Restore devices
            self.devices.clear()
            for d in data.get('devices', []):
                dev = AdvancedDevice.from_dict(d)
                self.devices[dev.name] = dev

            # Restore topology
            self.network_topology.clear()
            for name in self.devices.keys():
                self.network_topology.add_node(name)
            for e in data.get('edges', []):
                u = e.get('u')
                v = e.get('v')
                attrs = {
                    'delay_ms': (e.get('attrs', {}) or {}).get('delay_ms', LINK_DEFAULTS['delay_ms']),
                    'loss_rate': (e.get('attrs', {}) or {}).get('loss_rate', LINK_DEFAULTS['loss_rate']),
                    'bandwidth_mbps': (e.get('attrs', {}) or {}).get('bandwidth_mbps', LINK_DEFAULTS['bandwidth_mbps']),
                }
                if u in self.devices and v in self.devices:
                    self.network_topology.add_edge(u, v, **attrs)

            # Restore positions and settings
            self.node_positions = data.get('node_positions', {})
            settings = data.get('settings', {})
            self.dark_mode = bool(settings.get('dark_mode', self.dark_mode))
            self.loss_rate = float(settings.get('loss_rate', self.loss_rate))
            self.rto_ms = int(settings.get('rto_ms', self.rto_ms))

            # Restore analyzer (non-fatal if missing)
            analyzer_data = data.get('analyzer')
            if analyzer_data:
                try:
                    self.packet_analyzer = PacketAnalyzer.from_dict(analyzer_data)
                except Exception:
                    pass

            # Redraw UI with restored theme
            self.apply_theme()
            self.refresh_topology()
            messagebox.showinfo("Success", "Simulation loaded successfully.")
            # Refresh analyzer UI if we loaded packets
            self.update_packet_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load simulation: {e}")
        
        
    def highlight_packet_path(self, packet: NetworkPacket, current_node: str):
        """Draw highlight over the traversed portion of the path; clears previous highlights only."""
        # Clear old highlights
        self.topology_canvas.delete('hl')

        if not packet.path or current_node not in packet.path:
            return

        idx = packet.path.index(current_node)
        colors = self.current_colors()
        for i in range(1, idx + 1):
            prev_node = packet.path[i - 1]
            curr_node = packet.path[i]
            items1 = self.topology_canvas.find_withtag(prev_node)
            items2 = self.topology_canvas.find_withtag(curr_node)
            if items1 and items2:
                x1, y1 = self.topology_canvas.coords(items1[0])[:2]
                x2, y2 = self.topology_canvas.coords(items2[0])[:2]
                self.topology_canvas.create_line(x1, y1, x2, y2, fill=colors['hl'], width=2, tags=('hl',))
                    
    def on_close(self):
        plt.close('all')
        self.root.destroy()

    def toggle_dark_mode(self):
        """Toggle theme and redraw UI."""
        self.dark_mode = not self.dark_mode
        self.apply_theme()
        self.refresh_topology()


if __name__ == "__main__":
    simulator = AdvancedNetworkSimulator()
    simulator.root.protocol("WM_DELETE_WINDOW", simulator.on_close)
    simulator.root.mainloop()