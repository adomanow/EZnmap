#!/usr/bin/env python3

import sys
import os

import gi
gi.require_version('Gdk', '3.0')
from gi.repository import Gdk

if len(sys.argv) != 4:
    print("""{0} - Output a PNG from Nmap XML
    Usage: {0} <scan.xml> <out.png> <width_in_pixels>""".format(sys.argv[0]))
    sys.exit(1)

# Add the path to Zenmap modules
zenmap_path = os.path.join(os.path.dirname(__file__), "nmap/zenmap")
if not os.path.exists(zenmap_path):
    print(f"Error: Zenmap path '{zenmap_path}' does not exist.")
    sys.exit(1)

sys.path.insert(0, zenmap_path)

try:
    from zenmapGUI.TopologyPage import TopologyPage
    from zenmapCore.NetworkInventory import NetworkInventory
except ImportError as e:
    print(f"Error importing Zenmap modules: {e}")
    sys.exit(1)

# Initialize the TopologyPage
try:
    t = TopologyPage(NetworkInventory(sys.argv[1]))
except Exception as e:
    print(f"Error initializing TopologyPage: {e}")
    sys.exit(1)

# Set the pixel size for the output image
try:
    pix = int(sys.argv[3])
except ValueError:
    print("Error: Width in pixels must be an integer.")
    sys.exit(1)

# Activate fisheye mode
t.fisheye.active_fisheye()
t.fisheye.show()

# Update the interest factor to 10.0
t.fisheye._ControlFisheye__interest.set_value(10.0)  # Directly update Gtk Adjustment
t.fisheye._ControlFisheye__update_fisheye()         # Ensure fisheye updates

# Set up the radial network and save the drawing
allocation = Gdk.Rectangle()
allocation.x = 0
allocation.y = 0
allocation.width = pix
allocation.height = pix

t.radialnet.set_allocation(allocation)
t.update_radialnet()

try:
    output_path = os.path.abspath(sys.argv[2])
    t.radialnet.save_drawing_to_file(output_path)
    print(f"Saved PNG to {output_path}")
except Exception as e:
    print(f"Error saving PNG: {e}")
    sys.exit(1)

