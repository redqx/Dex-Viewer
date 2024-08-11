import os
import sys
from PyQt5.QtWidgets import QApplication, QStyleFactory

# 自定义
from Page import Page_Home

if __name__ == '__main__':

    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion')) #主题修改成Fusion Style：

    home=Page_Home()
    home.show()

    app.exec()


