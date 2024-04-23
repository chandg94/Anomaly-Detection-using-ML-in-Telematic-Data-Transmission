#!/usr/bin/python3
# This is the server to which our client/BBB connects
# Importing required modules
import os
from PyQt5 import QtWidgets, QtCore, uic
from pyqtgraph import PlotWidget, plot
import pyqtgraph as pg
import sys  # We need sys so that we can pass argv to QApplication
import csv
from pandas import *
import time
import numpy as np

class MainWindow(QtWidgets.QMainWindow):

    def __init__(self, *args, **kwargs):
        super(MainWindow, self).__init__(*args, **kwargs)
        uic.loadUi('GUI.ui', self)
        #self.graphWidget = pg.PlotWidget()
        #self.setCentralWidget(self.graphWidget)
        self.data = read_csv("eventdata.csv")
        self.xdata = self.data['Time'].tolist()
        self.ydata = self.data['SPN'].tolist()
        self.y2data = self.data['Flag'].tolist()
        self.y3data = self.data['PredHigh'].tolist()
        self.y4data = self.data['PredLow'].tolist()
        self.graphWidget.setBackground('w')
        # Add Title
        self.graphWidget.setTitle('<h1 style="color:Black;">Engine RPM vs Time</h1>')
        pg.TextItem(html='<p style="color:red;">- - - :Predicted RPM Range </p><p style="color:violet;">--- :Actual RPM </p><p style="color:blue;"> o :Anomalous Data</p>') # color="b", size="18pt")
        # Add Axis Labels
        styles = {"color": "#000", "font-size": "20px"}
        self.graphWidget.setLabel("left", "Engine RPM", **styles)
        self.graphWidget.setLabel("bottom", "Time", **styles)
        # Add legend
        #self.graphWidget.addLegend()
        # Add grid
        self.graphWidget.showGrid(x=True, y=True)
        self.data_line = self.graphWidget.plot(self.xdata, self.ydata)

        # Setup a timer to trigger the redraw by calling update_plot.
        self.timer = QtCore.QTimer()
        self.timer.setInterval(100)
        self.timer.timeout.connect(self.update_plot)
        self.timer.start()

    def update_plot(self):
        # Drop off the first y element, append a new one.
        self.data = read_csv("eventdata.csv")
        self.xdata = self.data['Time'].tolist()
        self.ydata = self.data['SPN'].tolist()
        self.y2data = self.data['Flag'].tolist()
        self.y3data = self.data['PredHigh'].tolist()
        self.y4data = self.data['PredLow'].tolist()
        pen1 = pg.mkPen(color=(191, 100, 237))
        self.data_line.setData(self.xdata, self.ydata, pen = pen1)
        list2 = []
        list3 = []
        list4 = []
        for i,j in zip(self.xdata,self.y2data):
            if j>0:
                k = 0
                list2.append(i)
                list3.append(j)
                list4.append(k)
        np1 = np.asarray(list4)
        self.graphWidget.plot(list2, list3, connect=np1, symbol = 'o')
        pen = pg.mkPen(color=(230, 87, 21), style=QtCore.Qt.DashLine)
        self.graphWidget.plot(self.xdata, self.y3data,pen=pen)
        self.graphWidget.plot(self.xdata, self.y4data,pen=pen)


app = QtWidgets.QApplication(sys.argv)
main = MainWindow()
main.show()
sys.exit(app.exec_())
