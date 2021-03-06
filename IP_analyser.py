#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# GUI module generated by PAGE version 7.4
#  in conjunction with Tcl version 8.6
#    Jun 08, 2022 12:48:10 PM BST  platform: Windows NT

import sys
import tkinter as tk
import tkinter.ttk as ttk
from tkinter.constants import *

import IP_analyser_support

class Toplevel1:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''
        _bgcolor = '#d9d9d9'  # X11 color: 'gray85'
        _fgcolor = '#000000'  # X11 color: 'black'
        _compcolor = 'gray40' # X11 color: #666666
        _ana1color = '#c3c3c3' # Closest X11 color: 'gray76'
        _ana2color = 'beige' # X11 color: #f5f5dc
        _tabfg1 = 'black' 
        _tabfg2 = 'black' 
        _tabbg1 = 'grey75' 
        _tabbg2 = 'grey89' 
        _bgmode = 'light' 
        self.style = ttk.Style()
        if sys.platform == "win32":
            self.style.theme_use('winnative')
        self.style.configure('.',background=_bgcolor, foreground=_fgcolor, font="TkDefaultFont")
        self.style.map('.',background=
            [('selected', _compcolor), ('active',_ana2color)])

        top.geometry("600x451+520+407")
        top.minsize(120, 1)
        top.maxsize(4612, 1525)
        top.resizable(1,  1)
        top.title("Bond")
        top.configure(background="#d9d9d9", highlightbackground="#d9d9d9", highlightcolor="black")

        self.top = top
        self.ip_list = []
        self.total_scanned = 0
        self.total_todo = 0

        global _images
        _images = (
         tk.PhotoImage("img_close", data='''R0lGODlhDAAMAIQUADIyMjc3Nzk5OT09PT
                 8/P0JCQkVFRU1NTU5OTlFRUVZWVmBgYGF hYWlpaXt7e6CgoLm5ucLCwszMzNbW
                 1v//////////////////////////////////// ///////////yH5BAEKAB8ALA
                 AAAAAMAAwAAAUt4CeOZGmaA5mSyQCIwhCUSwEIxHHW+ fkxBgPiBDwshCWHQfc5
                  KkoNUtRHpYYAADs= '''),
         tk.PhotoImage("img_close_white", data='''R0lGODlhDAAMAPQfAM3NzcjI
                yMbGxsLCwsDAwL29vbq6urKysrGxsa6urqmpqZ+fn56enpaWloSEhF9fX0ZGR
                j09PTMzMykpKQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///yH
                5BAEKAB8ALAAAAAAMAAwAAAUt4CeOZGmaA5mSyQCIwhCUSwEIxHHW+fkxBgPi
                BDwshCWHQfc5KkoNUtRHpYYAADs='''),
         tk.PhotoImage("img_closeactive", data='''R0lGODlhDAAMAIQcALwuEtIzFL46
                 INY0Fdk2FsQ8IdhAI9pAIttCJNlKLtpLL9pMMMNTP cVTPdpZQOBbQd60rN+1rf
                 Czp+zLxPbMxPLX0vHY0/fY0/rm4vvx8Pvy8fzy8P//////// ///////yH5BAEK
                 AB8ALAAAAAAMAAwAAAVHYLQQZEkukWKuxEgg1EPCcilx24NcHGYWFhx P0zANBE
                 GOhhFYGSocTsax2imDOdNtiez9JszjpEg4EAaA5jlNUEASLFICEgIAOw== '''),
         tk.PhotoImage("img_closepressed", data='''R0lGODlhDAAMAIQeAJ8nD64qELE
                 rELMsEqIyG6cyG7U1HLY2HrY3HrhBKrlCK6pGM7lD LKtHM7pKNL5MNtiViNaon
                  +GqoNSyq9WzrNyyqtuzq+O0que/t+bIwubJw+vJw+vTz+zT z////////yH5BAE
                 KAB8ALAAAAAAMAAwAAAVJIMUMZEkylGKuwzgc0kPCcgl123NcHWYW Fs6Gp2mYB
                 IRgR7MIrAwVDifjWO2WwZzpxkxyfKVCpImMGAeIgQDgVLMHikmCRUpMQgA7 ''')
        )
        if _bgmode == "dark":
            self.style.element_create("close", "image", "img_close_white",
               ('active', 'pressed',  'img_closepressed'),
               ('active', 'alternate', 'img_closeactive'), border=8, sticky='')
        else:
            self.style.element_create("close", "image", "img_close",
               ('active', 'pressed',  'img_closepressed'),
               ('active', 'alternate', 'img_closeactive'), border=8, sticky='')

        self.style.layout("ClosetabNotebook", [("ClosetabNotebook.client",
                                     {"sticky": "nswe"})])
        self.style.layout("ClosetabNotebook.Tab", [
            ("ClosetabNotebook.tab",
              { "sticky": "nswe",
                "children": [
                    ("ClosetabNotebook.padding", {
                        "side": "top",
                        "sticky": "nswe",
                        "children": [
                            ("ClosetabNotebook.focus", {
                                "side": "top",
                                "sticky": "nswe",
                                "children": [
                                    ("ClosetabNotebook.label", {"side":
                                      "left", "sticky": ''}),
                                    ("ClosetabNotebook.close", {"side":
                                        "left", "sticky": ''}),]})]})]})])

        def treeview_sort_column(self, tv, col, reverse):
            l = [(tv.set(k, col), k) for k in tv.get_children('')]
            l.sort(reverse=reverse)

            # rearrange items in sorted positions
            for index, (val, k) in enumerate(l):
                tv.move(k, '', index)

            # reverse sort next time
            tv.heading(col, command=lambda: \
                       treeview_sort_column(self, tv, col, not reverse))

        self.style.map('ClosetabNotebook.Tab', background =
            [('selected', _bgcolor), ('active', _tabbg1),
            ('!active', _tabbg2)], foreground =
            [('selected', _fgcolor), ('active', _tabfg1), ('!active', _tabfg2)])
        PNOTEBOOK="ClosetabNotebook"
        self.PNotebook1 = ttk.Notebook(self.top)
        self.PNotebook1.place(relx=0.0, rely=0.0, relheight=1.013
                , relwidth=1.007)
        self.PNotebook1.configure(style=PNOTEBOOK)
        self.PNotebook1_t1 = tk.Frame(self.PNotebook1)
        self.PNotebook1.add(self.PNotebook1_t1, padding=3)
        self.PNotebook1.tab(0, text='''IP List''', compound="left"
                ,underline='''-1''', )
        self.PNotebook1_t1.configure(background="#d9d9d9", highlightbackground="#d9d9d9", highlightcolor="black")
        
        self.PNotebook1_t2 = tk.Frame(self.PNotebook1)
        self.PNotebook1.add(self.PNotebook1_t2, padding=3)
        self.PNotebook1.tab(1, text='''VirusTotal''', compound="left"
                ,underline='''-1''', state="disabled")
        self.PNotebook1_t2.configure(background="#d9d9d9", highlightbackground="#d9d9d9", highlightcolor="black")
        
        self.PNotebook1_t3 = tk.Frame(self.PNotebook1)
        self.PNotebook1.add(self.PNotebook1_t3, padding=3)
        self.PNotebook1.tab(2, text='''ipinfo''', compound="left"
                      ,underline='''-1''', state="disabled")
        self.PNotebook1_t3.configure(background="#d9d9d9", highlightbackground="#d9d9d9", highlightcolor="black")
        
        self.PNotebook1_t4 = tk.Frame(self.PNotebook1)
        self.PNotebook1.add(self.PNotebook1_t4, padding=3)
        self.PNotebook1.tab(3, text='''vpnapi''', compound="left"
                ,underline='''-1''', state="disabled")
        self.PNotebook1_t4.configure(background="#d9d9d9", highlightbackground="#d9d9d9", highlightcolor="black")

        self.PNotebook1_t5 = tk.Frame(self.PNotebook1)
        self.PNotebook1.add(self.PNotebook1_t5, padding=3)
        self.PNotebook1.tab(4, text='''AbuseIPDB''', compound="left"
                ,underline='''-1''', state="disabled")
        self.PNotebook1_t5.configure(background="#d9d9d9", highlightbackground="#d9d9d9", highlightcolor="black")

        self.Label1 = tk.Label(self.PNotebook1_t1)
        self.Label1.place(relx=0.083, rely=0.023, height=21, width=214)
        self.Label1.configure(activebackground="#f9f9f9", anchor='w', background="#d9d9d9", compound='left', 
                              disabledforeground="#a3a3a3", foreground="#000000", highlightbackground="#d9d9d9", 
                              highlightcolor="black", text='''Enter list of IP addresses or browse file''')

        self.Label2 = tk.Label(self.PNotebook1_t1)
        self.Label2.place(relx=0.567, rely=0.023, height=21, width=164)
        self.Label2.configure(activebackground="#f9f9f9", anchor='w', background="#d9d9d9", compound='left', 
                              disabledforeground="#a3a3a3", foreground="#000000", highlightbackground="#d9d9d9", 
                              highlightcolor="black", text='''List of imported IP addresses''')

        self.Label3 = tk.Label(self.PNotebook1_t1)
        self.Label3.place(relx=0.017, rely=0.928, height=21, width=154)
        self.Label3.configure(activebackground="#f9f9f9", anchor='w', background="#d9d9d9", compound='left', 
                              disabledforeground="#a3a3a3", foreground="#000000", highlightbackground="#d9d9d9", 
                              highlightcolor="black", text="")

        self.Text1 = tk.Text(self.PNotebook1_t1)
        self.Text1.place(relx=0.083, rely=0.07, relheight=0.708, relwidth=0.34)
        self.Text1.configure(background="white", font="TkTextFont", foreground="black", 
                             highlightbackground="#d9d9d9", 
                             highlightcolor="black", insertbackground="black", selectbackground="#c4c4c4", 
                             selectforeground="black", wrap="word")

        self.Button1 = tk.Button(self.PNotebook1_t1)
        self.Button1.place(relx=0.517, rely=0.812, height=34, width=127)
        self.Button1.configure(activebackground="beige", activeforeground="#000000", background="#d9d9d9", 
                               compound='left', disabledforeground="#a3a3a3", foreground="#000000", 
                               highlightbackground="#d9d9d9", highlightcolor="black", padx="10", pady="0", 
                               text='''Analyse''', state="disabled")
        self.Button1.configure(command=lambda: IP_analyser_support.analyse_button(self, self.Button3,
                                                                                  self.PNotebook1, 
                                                                                  self.Scrolledtreeview1, 
                                                                                  self.Scrolledtreeview2, 
                                                                                  self.Scrolledtreeview3,
                                                                                  self.Scrolledtreeview4))

        self.Button2 = tk.Button(self.PNotebook1_t1)
        self.Button2.place(relx=0.267, rely=0.812, height=34, width=127)
        self.Button2.configure(activebackground="beige", activeforeground="#000000", background="#d9d9d9", 
                               compound='left', disabledforeground="#a3a3a3", foreground="#000000", 
                               highlightbackground="#d9d9d9", highlightcolor="black", padx="15", pady="0", 
                               text='''Browse''')
        self.Button2.configure(command=lambda: IP_analyser_support.browse_button(self))

        self.Button3 = tk.Button(self.PNotebook1_t1)
        self.Button3.place(relx=0.75, rely=0.812, height=34, width=127)
        self.Button3.configure(activebackground="beige", activeforeground="#000000", background="#d9d9d9", 
                               compound='left', disabledforeground="#a3a3a3", foreground="#000000", 
                               highlightbackground="#d9d9d9", highlightcolor="black", padx="15", pady="0", 
                               text='''Export''', state="disabled")
        self.Button3.configure(command=lambda: IP_analyser_support.export_button(self.Label3))

        self.Button4 = tk.Button(self.PNotebook1_t1)
        self.Button4.place(relx=0.033, rely=0.812, height=34, width=127)
        self.Button4.configure(activebackground="beige", activeforeground="#000000", background="#d9d9d9", 
                               compound='left', disabledforeground="#a3a3a3", foreground="#000000", 
                               highlightbackground="#d9d9d9", highlightcolor="black", padx="15", pady="0", 
                               text='''Import from text''')
        self.Button4.configure(command=lambda: IP_analyser_support.import_button(self))

        self.TProgressbar1 = ttk.Progressbar(self.PNotebook1_t1)
        self.TProgressbar1.place(relx=0.817, rely=0.928, relwidth=0.167, relheight=0.0, height=22)

        self.style.configure('Treeview',  font="TkDefaultFont")
        self.Scrolledtreeview0 = ScrolledTreeView(self.PNotebook1_t1, show="tree")
        self.Scrolledtreeview0.place(relx=0.567, rely=0.07, relheight=0.712, relwidth=0.35)
        self.Scrolledtreeview0.column("#0",width="191", minwidth="191", stretch="1", anchor="w")

        self.Scrolledtreeview1 = ScrolledTreeView(self.PNotebook1_t2)
        self.Scrolledtreeview1.place(relx=0.017, rely=0.023, relheight=0.947
                , relwidth=0.967)
        self.Scrolledtreeview1.configure(columns="Col1")
        self.Scrolledtreeview1.heading("#0",text="IP address", anchor="center")
        self.Scrolledtreeview1.column("#0",width="280", minwidth="20", stretch="1", anchor="w")
        self.Scrolledtreeview1.heading("Col1",text="Results", anchor="center")
        self.Scrolledtreeview1.heading("Col1",command=lambda: \
                     treeview_sort_column(self, self.Scrolledtreeview1, "Col1", False))
        self.Scrolledtreeview1.column("Col1",width="281", minwidth="20", stretch="1", anchor="w")

        self.Scrolledtreeview2 = ScrolledTreeView(self.PNotebook1_t3)
        self.Scrolledtreeview2.place(relx=0.017, rely=0.023, relheight=0.944
                , relwidth=0.958)
        self.Scrolledtreeview2.configure(columns="Col1")
        self.Scrolledtreeview2.heading("#0",text="IP address", anchor="center")
        self.Scrolledtreeview2.column("#0",width="278", minwidth="20", stretch="1", anchor="w")
        self.Scrolledtreeview2.heading("Col1",text="Country", anchor="center")
        self.Scrolledtreeview2.heading("Col1",command=lambda: \
                     treeview_sort_column(self, self.Scrolledtreeview2, "Col1", False))
        self.Scrolledtreeview2.column("Col1",width="278", minwidth="20", stretch="1", anchor="w")

        self.Scrolledtreeview3 = ScrolledTreeView(self.PNotebook1_t4)
        self.Scrolledtreeview3.place(relx=0.017, rely=0.023, relheight=0.944
                , relwidth=0.967)
        self.Scrolledtreeview3.configure(columns="Col1")
        self.Scrolledtreeview3.heading("#0",text="IP address", anchor="center")
        self.Scrolledtreeview3.column("#0",width="280", minwidth="20", stretch="1", anchor="w")
        self.Scrolledtreeview3.heading("Col1",text="Security Measure", anchor="center")
        self.Scrolledtreeview3.heading("Col1",command=lambda: \
                     treeview_sort_column(self, self.Scrolledtreeview3, "Col1", False))
        self.Scrolledtreeview3.column("Col1",width="281", minwidth="20", stretch="1", anchor="w")

        self.Scrolledtreeview4 = ScrolledTreeView(self.PNotebook1_t5)
        self.Scrolledtreeview4.place(relx=0.017, rely=0.023, relheight=0.944
                , relwidth=0.967)
        self.Scrolledtreeview4.configure(columns="Col1")
        self.Scrolledtreeview4.heading("#0",text="IP address", anchor="center")
        self.Scrolledtreeview4.column("#0",width="280", minwidth="20", stretch="1", anchor="w")
        self.Scrolledtreeview4.heading("Col1",text="Abuse Confidence Score", anchor="center")
        self.Scrolledtreeview4.heading("Col1",command=lambda: \
                     treeview_sort_column(self, self.Scrolledtreeview4, "Col1", False))
        self.Scrolledtreeview4.column("Col1",width="281", minwidth="20", stretch="1", anchor="w")

        self.PNotebook1.bind('<Button-1>',_button_press)
        self.PNotebook1.bind('<ButtonRelease-1>',_button_release)
        self.PNotebook1.bind('<Motion>',_mouse_over)
        self.PNotebook1.bind('<Button-1>',_button_press)
        self.PNotebook1.bind('<ButtonRelease-1>',_button_release)
        self.PNotebook1.bind('<Motion>',_mouse_over)

# The following code is add to handle mouse events with the close icons
# in PNotebooks widgets.
def _button_press(event):
    widget = event.widget
    element = widget.identify(event.x, event.y)
    if "close" in element:
        index = widget.index("@%d,%d" % (event.x, event.y))
        widget.state(['pressed'])
        widget._active = index

def _button_release(event):
    widget = event.widget
    if not widget.instate(['pressed']):
            return
    element = widget.identify(event.x, event.y)
    try:
        index = widget.index("@%d,%d" % (event.x, event.y))
    except tk.TclError:
        pass
    if "close" in element and widget._active == index:
        widget.forget(index)
        widget.event_generate("<<NotebookTabClosed>>")

    widget.state(['!pressed'])
    widget._active = None

def _mouse_over(event):
    widget = event.widget
    element = widget.identify(event.x, event.y)
    if "close" in element:
        widget.state(['alternate'])
    else:
        widget.state(['!alternate'])

# The following code is added to facilitate the Scrolled widgets you specified.
class AutoScroll(object):
    '''Configure the scrollbars for a widget.'''
    def __init__(self, master):
        #  Rozen. Added the try-except clauses so that this class
        #  could be used for scrolled entry widget for which vertical
        #  scrolling is not supported. 5/7/14.
        try:
            vsb = ttk.Scrollbar(master, orient='vertical', command=self.yview)
        except:
            pass
        hsb = ttk.Scrollbar(master, orient='horizontal', command=self.xview)
        try:
            self.configure(yscrollcommand=self._autoscroll(vsb))
        except:
            pass
        self.configure(xscrollcommand=self._autoscroll(hsb))
        self.grid(column=0, row=0, sticky='nsew')
        try:
            vsb.grid(column=1, row=0, sticky='ns')
        except:
            pass
        hsb.grid(column=0, row=1, sticky='ew')
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(0, weight=1)
        # Copy geometry methods of master  (taken from ScrolledText.py)
        methods = tk.Pack.__dict__.keys() | tk.Grid.__dict__.keys() \
                  | tk.Place.__dict__.keys()
        for meth in methods:
            if meth[0] != '_' and meth not in ('config', 'configure'):
                setattr(self, meth, getattr(master, meth))

    @staticmethod
    def _autoscroll(sbar):
        '''Hide and show scrollbar as needed.'''
        def wrapped(first, last):
            first, last = float(first), float(last)
            if first <= 0 and last >= 1:
                sbar.grid_remove()
            else:
                sbar.grid()
            sbar.set(first, last)
        return wrapped

    def __str__(self):
        return str(self.master)

def _create_container(func):
    '''Creates a ttk Frame with a given master, and use this new frame to
    place the scrollbars and the widget.'''
    def wrapped(cls, master, **kw):
        container = ttk.Frame(master)
        container.bind('<Enter>', lambda e: _bound_to_mousewheel(e, container))
        container.bind('<Leave>', lambda e: _unbound_to_mousewheel(e, container))
        return func(cls, container, **kw)
    return wrapped

class ScrolledTreeView(AutoScroll, ttk.Treeview):
    '''A standard ttk Treeview widget with scrollbars that will
    automatically show/hide as needed.'''
    @_create_container
    def __init__(self, master, **kw):
        ttk.Treeview.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)

import platform
def _bound_to_mousewheel(event, widget):
    child = widget.winfo_children()[0]
    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        child.bind_all('<MouseWheel>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-MouseWheel>', lambda e: _on_shiftmouse(e, child))
    else:
        child.bind_all('<Button-4>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Button-5>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-Button-4>', lambda e: _on_shiftmouse(e, child))
        child.bind_all('<Shift-Button-5>', lambda e: _on_shiftmouse(e, child))

def _unbound_to_mousewheel(event, widget):
    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        widget.unbind_all('<MouseWheel>')
        widget.unbind_all('<Shift-MouseWheel>')
    else:
        widget.unbind_all('<Button-4>')
        widget.unbind_all('<Button-5>')
        widget.unbind_all('<Shift-Button-4>')
        widget.unbind_all('<Shift-Button-5>')

def _on_mousewheel(event, widget):
    if platform.system() == 'Windows':
        widget.yview_scroll(-1*int(event.delta/120),'units')
    elif platform.system() == 'Darwin':
        widget.yview_scroll(-1*int(event.delta),'units')
    else:
        if event.num == 4:
            widget.yview_scroll(-1, 'units')
        elif event.num == 5:
            widget.yview_scroll(1, 'units')

def _on_shiftmouse(event, widget):
    if platform.system() == 'Windows':
        widget.xview_scroll(-1*int(event.delta/120), 'units')
    elif platform.system() == 'Darwin':
        widget.xview_scroll(-1*int(event.delta), 'units')
    else:
        if event.num == 4:
            widget.xview_scroll(-1, 'units')
        elif event.num == 5:
            widget.xview_scroll(1, 'units')
def start_up():
    IP_analyser_support.main()

if __name__ == '__main__':
    IP_analyser_support.main()




