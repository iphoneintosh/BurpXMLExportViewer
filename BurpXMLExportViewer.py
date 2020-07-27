from burp import IBurpExtender
from burp import ITab
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from burp import IParameter
from burp import IHttpService

from java.awt import BorderLayout
from java.util import ArrayList

from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JButton
from javax.swing import JPanel
from javax.swing import JFileChooser

from javax.swing.table import AbstractTableModel
from javax.xml.parsers import DocumentBuilderFactory
from javax.xml.parsers import DocumentBuilder

from threading import Lock
from org.w3c.dom import Node

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, AbstractTableModel):
	
	"""
		Implements IBurpExtender
	"""

	def	registerExtenderCallbacks(self, callbacks):
		
		# Save callbacks and helpers for later use
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		
		# Set extension name
		self._callbacks.setExtensionName("Burp XML Export Viewer")
		
		# Create the log and a lock on which to synchronize when adding log entries
		self._log = ArrayList()
		self._lock = Lock()
		
		# Main panel
		self._mainPanel = JPanel(BorderLayout())
		
		# Button to load Burp XML Export file
		self._loadButton = JButton('Select Burp XML Export File')
		self._loadButton.addActionListener(self.loadButtonTapped)
		self._mainPanel.add(self._loadButton, BorderLayout.PAGE_START)
		
		# File chooser for Burp XML Export file
		self._fc = JFileChooser()
		self._fc.setDialogTitle("Select Burp XML Export File")
		
		# Splitpane for table and request/response view
		self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._mainPanel.add(self._splitpane, BorderLayout.CENTER)
		
		# Table of log entries
		self._logTable = Table(self)
		self._scrollPane = JScrollPane(self._logTable)
		self._splitpane.setTopComponent(self._scrollPane)

		# Set column width of table
		self._logTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
		self._logTable.getColumnModel().getColumn(0).setPreferredWidth(20)
		self._logTable.getColumnModel().getColumn(1).setPreferredWidth(60)
		self._logTable.getColumnModel().getColumn(2).setPreferredWidth(70)
		self._logTable.getColumnModel().getColumn(3).setPreferredWidth(300)
		self._logTable.getColumnModel().getColumn(4).setPreferredWidth(500)
		self._logTable.getColumnModel().getColumn(5).setPreferredWidth(300)
		self._logTable.getColumnModel().getColumn(6).setPreferredWidth(100)
		self._logTable.getColumnModel().getColumn(7).setPreferredWidth(100)
		self._logTable.getColumnModel().getColumn(8).setPreferredWidth(100)
		self._logTable.getColumnModel().getColumn(9).setPreferredWidth(100)
		self._logTable.getColumnModel().getColumn(10).setPreferredWidth(230)
		self._logTable.getColumnModel().getColumn(11).setMaxWidth(100000)

		# Tabs with request and response viewers
		self._tabs = JTabbedPane()
		self._requestViewer = callbacks.createMessageEditor(self, False)
		self._responseViewer = callbacks.createMessageEditor(self, False)
		self._tabs.addTab("Request", self._requestViewer.getComponent())
		self._tabs.addTab("Response", self._responseViewer.getComponent())
		self._splitpane.setBottomComponent(self._tabs)
		
		# Customize UI components
		self._callbacks.customizeUiComponent(self._mainPanel)
		self._callbacks.customizeUiComponent(self._splitpane)
		self._callbacks.customizeUiComponent(self._logTable)
		self._callbacks.customizeUiComponent(self._scrollPane)
		self._callbacks.customizeUiComponent(self._tabs)
		
		# Add the custom tab to Burp's UI
		self._callbacks.addSuiteTab(self)
		
		return
	
	"""
		Helper Functions
	"""
	
	def loadButtonTapped(self, actionEvent):
		
		# Display the file chooser dialog
		retVal = self._fc.showOpenDialog(None)
		
		if retVal == JFileChooser.APPROVE_OPTION:
			self._file = self._fc.getSelectedFile()
			self.resetList() # clear the table from all previous entries
			self.parseXML(self._file) # parse the file and load all entries to the table
		else:
			print("Open command cancelled by user.")
	
	def parseXML(self, file):
		
		# Initialize XML stuff
		dbFactory = DocumentBuilderFactory.newInstance()
		dBuilder = dbFactory.newDocumentBuilder()
		doc = dBuilder.parse(file)
		doc.getDocumentElement().normalize()
		
		# All entries in Burp's XML Export File have tag <item>...</item>
		nodeList = doc.getElementsByTagName("item")

		for i in reversed(range(0, nodeList.getLength())):
			node = nodeList.item(i)
			
			if node.getNodeType() == Node.ELEMENT_NODE:
				info = {
					"time" : node.getElementsByTagName("time").item(0).getTextContent(),
					"url" : node.getElementsByTagName("url").item(0).getTextContent(),
					"host" : node.getElementsByTagName("host").item(0).getTextContent(),
					"port" : node.getElementsByTagName("port").item(0).getTextContent(),
					"protocol" : node.getElementsByTagName("protocol").item(0).getTextContent(),
					"method" : node.getElementsByTagName("method").item(0).getTextContent(),
					"path" : node.getElementsByTagName("path").item(0).getTextContent(),
					"extension" : node.getElementsByTagName("extension").item(0).getTextContent(),
					"request" : node.getElementsByTagName("request").item(0).getTextContent(),
					"status" : node.getElementsByTagName("status").item(0).getTextContent(),
					"responselength" : node.getElementsByTagName("responselength").item(0).getTextContent(),
					"mimetype" : node.getElementsByTagName("mimetype").item(0).getTextContent(),
					"response" : node.getElementsByTagName("response").item(0).getTextContent(),
					"comment" : node.getElementsByTagName("comment").item(0).getTextContent(),
					"highlight" : ""
				}
				
				logEntry = LogEntry(info)

				# Remove GET parameters from path component
				# Path component usually looks like this: /some/path/index.html?q=foo&z=faa
				info["path"] = info["path"].split("?")[0]

				# Extract GET/POST parameters
				params = []
				for param in self._helpers.analyzeRequest(logEntry).getParameters():
					if param.getType() == IParameter.PARAM_URL or param.getType() == IParameter.PARAM_BODY:
						params.append("{}={}".format(param.getName(), param.getValue()))
				info["params"] = ", ".join(params)

				self.addLogEntryToList(logEntry)

	def addLogEntryToList(self, logEntry):
		self._lock.acquire()
		row = self._log.size()
		self._log.add(logEntry)
		self.fireTableRowsInserted(row, row)
		self._lock.release()

	def resetList(self):
		self._lock.acquire()
		self._log.clear()
		self.fireTableRowsInserted(0,0)
		self._lock.release()

	"""
		Implements ITab
	"""

	def getTabCaption(self):
		return "Burp XML Export Viewer"
	
	def getUiComponent(self):
		return self._mainPanel

	"""
		Extends AbstractTableModel
	"""

	def getRowCount(self):
		try:
			return self._log.size()
		except:
			return 0

	def getColumnCount(self):
		return 12

	def getColumnName(self, columnIndex):
		if columnIndex == 0:
			return "#"
		if columnIndex == 1:
			return "Method"
		if columnIndex == 2:
			return "Protocol"
		if columnIndex == 3:
			return "Host"
		if columnIndex == 4:
			return "Path"
		if columnIndex == 5:
			return "Parameters"
		if columnIndex == 6:
			return "Status"
		if columnIndex == 7:
			return "Length"
		if columnIndex == 8:
			return "MIME type"
		if columnIndex == 9:
			return "Extension"
		if columnIndex == 10:
			return "Time"
		if columnIndex == 11:
			return "Comment"
		
		return ""

	def getValueAt(self, rowIndex, columnIndex):
		logEntry = self._log.get(rowIndex)
		
		if columnIndex == 0:
			return "{}".format(rowIndex)
		if columnIndex == 1:
			return logEntry._info["method"]
		if columnIndex == 2:
			return logEntry._info["protocol"]
		if columnIndex == 3:
			return logEntry.getHttpService().getHost()
		if columnIndex == 4:
			return logEntry._info["path"]
		if columnIndex == 5:
			return logEntry._info["params"]
		if columnIndex == 6:
			return logEntry._info["status"]
		if columnIndex == 7:
			return logEntry._info["responselength"]
		if columnIndex == 8:
			return logEntry._info["mimetype"]
		if columnIndex == 9:
			return logEntry._info["extension"]
		if columnIndex == 10:
			return logEntry._info["time"]
		if columnIndex == 11:
			return logEntry._info["comment"]
		
		return ""

	"""
		Implements IMessageEditorController
		Allows request and response viewers to obtain details about the messages being displayed
	"""
	
	def getHttpService(self):
		return self._currentlyDisplayedItem.getHttpService()

	def getRequest(self):
		return self._currentlyDisplayedItem.getRequest()

	def getResponse(self):
		return self._currentlyDisplayedItem.getResponse()

"""
	Extends JTable
	Handles cell selection
"""
	
class Table(JTable):
	def __init__(self, extender):
		self._extender = extender
		self.setModel(extender)
	
	def changeSelection(self, row, col, toggle, extend):
		logEntry = self._extender._log.get(row)
		self._extender._requestViewer.setMessage(logEntry.getRequest(), True)
		self._extender._responseViewer.setMessage(logEntry.getResponse(), False)
		self._extender._currentlyDisplayedItem = logEntry
		
		JTable.changeSelection(self, row, col, toggle, extend)

"""
	Custom class that represents individual log entry
	Holds details of each log entry that is displayed in table and request/response viewer
"""

class LogEntry(IHttpRequestResponse):
	def __init__(self, info):
		self._info = info
		self._httpService = HttpService(info["host"], info["port"], info["protocol"])
		self._request = bytearray(info["request"], "utf8")
		self._response = bytearray(info["response"], "utf8")
		self._comment = info["comment"]
		self._highlight = info["highlight"]

	def getRequest(self):
		return self._request

	def setRequest(self, request):
		self._request = request

	def getResponse(self):
		return self._response

	def setResponse(self, response):
		self._response = response

	def getComment(self):
		return self._comment

	def setComment(self, comment):
		self._comment = comment

	def getHighlight(self):
		return self._highlight

	def setHighlight(self, highlight):
		self._highlight = highlight

	def getHttpService(self):
		return self._httpService

	def setHttpService(self, httpService):
		self._httpService = httpService

class HttpService(IHttpService):
	def __init__(self, host, port, protocol):
		self._host = host
		self._port = int(port)
		self._protocol = protocol

	def getHost(self):
		return str(self._host)

	def getPort(self):
		return int(self._port)

	def getProtocol(self):
		return str(self._protocol)
