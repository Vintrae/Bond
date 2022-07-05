#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# Support module generated by PAGE version 7.4
#  in conjunction with Tcl version 8.6
#    Jun 08, 2022 12:30:34 AM BST  platform: Windows NT
#    Jun 08, 2022 12:38:28 AM BST  platform: Windows NT

import sys
import tkinter as tk
import tkinter.ttk as ttk
from tkinter.constants import *
from tkinter.filedialog import asksaveasfilename, askopenfilename
from pprint import pprint
import time
import json

import pandas as pd

import IP_analyser
import ip_apis

colour_palette = {
    'green':'#a4ff91',
    'yellow':'#ebef70',
    'red':'#ff867d'
}

def main(*args):
    '''Main entry point for the application.'''
    global root
    root = tk.Tk()
    root.protocol( 'WM_DELETE_WINDOW' , root.destroy)
    # Creates a toplevel widget.
    global _top1, _w1
    _top1 = root
    _w1 = IP_analyser.Toplevel1(_top1)
    root.iconbitmap("icon.ico")
    root.ip_data = []
    root.mainloop()

def print(*args):
    print('IP_analyser_support.print')
    for arg in args:
        print ('another arg:', arg)
    sys.stdout.flush()
    
def browse_button(parent):
    parent.ip_list = []
    file_name = askopenfilename(defaultextension=".txt", filetypes=(("Text File", "*.txt"),("All Files", "*.*")))
    with open(file_name, 'r') as f:
        for line in f:
            stripped_line = line.strip()
            parent.ip_list.append(stripped_line.replace("[.]", "."))
    parent.ip_list = [ip.replace('"', "") for ip in parent.ip_list]
    parent.ip_list = [ip.replace(",", "") for ip in parent.ip_list]
    while '' in parent.ip_list:
            parent.ip_list.remove('')
    update_imported(parent)

def import_button(parent):
    parent.ip_list = parent.Text1.get("1.0", tk.END)
    parent.ip_list = parent.ip_list.split('\n')
    parent.ip_list = [ip.replace("[.]", ".") for ip in parent.ip_list]
    parent.ip_list = [ip.replace('"', "") for ip in parent.ip_list]
    parent.ip_list = [ip.replace(",", "") for ip in parent.ip_list]
    while '' in parent.ip_list:
        parent.ip_list.remove('')
    update_imported(parent)

def export_button(label):
    label.configure(text="")
    file_name = asksaveasfilename(confirmoverwrite=True, defaultextension=".xlsx", filetypes=(("Excel file", "*.xlsx"),("All Files", "*.*")))
    if file_name:
        sheet_index = 1
        for sheet in root.ip_data:
            sheet_data = pd.DataFrame()
            for ip in sheet:
                df = pd.json_normalize(ip)
                sheet_data = pd.concat([sheet_data, df], ignore_index=True)
            write_excel(file_name, 'Sheet {}'.format(sheet_index), sheet_data)
            sheet_index += 1
        label.configure(text="Successfully exported data.")

def analyse_button(parent, button, tab, treeview, treeview2, treeview3, treeview4):
    ip_list = parent.ip_list.copy()
    root.ip_data = []
    
    # Get VirusTotal data.
    treeview.delete(*treeview.get_children()) 
    vt_queued_domains = ip_apis.vt_domain_scan(ip_list)
    time.sleep(1) 
    vt_domain_report = ip_apis.vt_results(vt_queued_domains)
    root.ip_data.append(vt_domain_report)
    
    index = 0
    for result in vt_domain_report:
        if 'resource' in result:
            treeview.insert('', "end", str(index), text=result['resource'], values=("{}/{}".format(result['positives'], result['total'])))
        for scan in result['scans']:
            # Create tag for colouring purposes.
            tag = None
            if result['scans'][scan]['detected']:
                tag = 'red'
            else:
                tag = 'green'
            treeview.insert(str(index), "end", tags=(tag), text=scan, values=(str(result['scans'][scan]['detected'])))
        index += 1
    treeview.tag_configure('red', background=colour_palette['red'])
    treeview.tag_configure('green', background=colour_palette['green'])

    tab.tab(1, state="normal")

    # Get ipinfo data.
    treeview2.delete(*treeview2.get_children())

    ipinfo_data = ip_apis.ipinfo_results(ip_list)
    root.ip_data.append(ipinfo_data)
    index = 0
    for result in ipinfo_data:
        if 'ip' in result:
            if 'country' in result:
                treeview2.insert('', "end", str(index), text=result['ip'], values=(result['country']))
            else:
                treeview2.insert('', "end", str(index), text=result['ip'])
            for key in result:
                if key != 'ip':
                    treeview2.insert(str(index), "end", text="{}".format(key), values=("{}".format(result[key])))
            index += 1

    tab.tab(2, state="normal")

    # Get vpnapi data.
    treeview3.delete(*treeview3.get_children())

    vpnapi_data = ip_apis.vpnapi_results(ip_list)
    root.ip_data.append(vpnapi_data)
    index = 0
    tag = None
    for result in vpnapi_data:
        if 'security' in result:
            sec_value = None
            for value in result['security']:
                if result['security'][value] is True:
                    tag = 'yellow'
                    sec_value = str(value)
            if tag is not None:
                treeview3.insert('', "end", str(index), tags=(tag), text=result['ip'], values=(sec_value))
                tag = None
            else:
                treeview3.insert('', "end", str(index), text=result['ip'])
            for key in result:
                if key != 'ip':
                    for subkey in result[key]:
                        treeview3.insert(str(index), "end", text="{}".format(subkey), values=("{}".format(result[key][subkey])))
            index += 1
    treeview3.tag_configure('yellow', background=colour_palette['yellow'])        
    
    tab.tab(3, state="normal")

    # Get AbuseIPDB data.
    treeview4.delete(*treeview4.get_children())

    abuseipdb_data = ip_apis.abuseipdb_results(ip_list)
    root.ip_data.append(abuseipdb_data)
    index = 0
    tag = None
    for result in abuseipdb_data:
        if 'data' in result and 'ipAddress' in result['data']:
            confidence_score = None
            score = result['data']['abuseConfidenceScore']
            if score == 0:
                tag = 'green'
            elif score <= 50:
                tag = 'yellow'
            else:
                tag = 'red'
            confidence_score = str(score)
            if tag is not None:
                treeview4.insert('', "end", str(index), tags=(tag), text=result['data']['ipAddress'], values=(result['data']['abuseConfidenceScore']))
                tag = None
            else:
                treeview4.insert('', "end", str(index), text=result['data']['ipAddress'])
            for key in result['data']:
                if key != 'ipAddress' and key != 'reports':
                    treeview4.insert(str(index), "end", text="{}".format(key), values=("{}".format(result['data'][key])))
            index += 1
    treeview4.tag_configure('yellow', background=colour_palette['yellow'])        
    
    tab.tab(4, state="normal")

    button.configure(state="normal")
    parent.Label3.configure(text="Analysis complete.")

def write_excel(filename,sheetname,dataframe):
    try:
        with pd.ExcelWriter(filename, engine='openpyxl', mode='a', if_sheet_exists="replace") as writer: 
                dataframe.to_excel(writer, sheet_name=sheetname, index=False)
    except:
        with pd.ExcelWriter(filename, engine='openpyxl', mode='w') as writer: 
                dataframe.to_excel(writer, sheet_name=sheetname, index=False)

def update_imported(parent):
    parent.treeview0.delete(*parent.treeview0.get_children())
    if parent.ip_list:
        for ip in parent.ip_list:
            parent.Scrolledtreeview0.insert('', "end", text=ip)
        parent.Label3.configure(text="Successfully imported IPs.")
        parent.Button1.configure(state="normal")
        parent.Button3.configure(state="normal")
    else:
        parent.Label3.configure(text="No IPs found.")
        parent.Button1.configure(state="disabled")
        parent.Button3.configure(state="disabled")
    

if __name__ == '__main__':
    IP_analyser.start_up()





